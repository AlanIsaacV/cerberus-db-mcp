package redisgate

import "strconv"

type refusal struct {
	reason Reason
	detail string
	arg    int
}

func refuse(reason Reason, detail string) *refusal {
	return &refusal{reason: reason, detail: detail}
}

func itoa(n int) string {
	return strconv.Itoa(n)
}

func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return itoa(n) + " " + word + "s"
}

func arityRange(args []string, lo, hi int) *refusal {
	if len(args) >= lo && len(args) <= hi {
		return nil
	}
	if lo == hi {
		return refuse(ReasonWrongArity, "the command takes "+plural(lo, "argument")+" after its name")
	}
	return refuse(ReasonWrongArity, "the command takes between "+itoa(lo)+" and "+itoa(hi)+" arguments after its name")
}

func fixed(n int) func(*Gate, []string) *refusal {
	return func(_ *Gate, args []string) *refusal {
		return arityRange(args, n, n)
	}
}

func variadic(prefix, min int, what string) func(*Gate, []string) *refusal {
	return func(g *Gate, args []string) *refusal {
		if len(args) < prefix+min {
			return refuse(ReasonWrongArity, "the command takes at least "+plural(prefix+min, "argument")+" after its name")
		}
		if n := len(args) - prefix; n > g.limits.MaxElements {
			return refuse(ReasonTooManyElements,
				"the number of "+what+" is "+itoa(n)+"; at most "+itoa(g.limits.MaxElements)+" "+what+" are accepted per call")
		}
		return nil
	}
}

func parseInt(s string) (int64, bool) {
	if s == "" || len(s) > 20 {
		return 0, false
	}
	digits := s
	if digits[0] == '-' {
		digits = digits[1:]
	}
	if digits == "" || digits[0] < '0' || digits[0] > '9' {
		return 0, false
	}
	if digits[0] == '0' && (len(digits) > 1 || len(s) > 1) {
		return 0, false
	}
	for i := 1; i < len(digits); i++ {
		if digits[i] < '0' || digits[i] > '9' {
			return 0, false
		}
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

func validCursor(s string) bool {
	if s == "" || len(s) > 20 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	_, err := strconv.ParseUint(s, 10, 64)
	return err == nil
}

func intArg(name, value string) (int64, *refusal) {
	n, ok := parseInt(value)
	if !ok {
		return 0, refuse(ReasonInvalidArgument, name+" must be an integer")
	}
	return n, nil
}

func needValue(args []string, i int, option string) *refusal {
	if i+1 >= len(args) {
		return refuse(ReasonWrongArity, option+" needs a value")
	}
	return nil
}

func duplicate(option string) *refusal {
	return refuse(ReasonDuplicateArgument, option+" is given more than once")
}

func unknownArgument(index int) *refusal {
	return &refusal{reason: ReasonUnknownArgument, arg: index + 1}
}

func (g *Gate) countOption(value string) *refusal {
	n, ref := intArg("COUNT", value)
	if ref != nil {
		return ref
	}
	if n < 1 {
		return refuse(ReasonInvalidArgument, "COUNT must be at least 1")
	}
	if n > int64(g.limits.MaxCount) {
		return refuse(ReasonCountTooLarge, "COUNT must be at most "+itoa(g.limits.MaxCount))
	}
	return nil
}

func missingCount(g *Gate) *refusal {
	return refuse(ReasonMissingCount, "COUNT is required and must be between 1 and "+itoa(g.limits.MaxCount))
}

func (g *Gate) window(start, stop string) *refusal {
	a, ref := intArg("start", start)
	if ref != nil {
		return ref
	}
	b, ref := intArg("stop", stop)
	if ref != nil {
		return ref
	}
	if a < 0 || b < 0 {
		return refuse(ReasonUnboundedWindow,
			"start and stop must be non-negative; a negative index counts from the end, so the window grows with the value")
	}
	if b >= a && b-a >= int64(g.limits.MaxElements) {
		return refuse(ReasonWindowTooLarge,
			"stop - start + 1 must be at most "+itoa(g.limits.MaxElements)+"; lower stop")
	}
	return nil
}

func scanOptions(g *Gate, args []string, offset int, extra string) *refusal {
	var match, count, typ, flag bool
	for i := 0; i < len(args); i++ {
		switch {
		case asciiEqualFold(args[i], "match"):
			if match {
				return duplicate("MATCH")
			}
			if ref := needValue(args, i, "MATCH"); ref != nil {
				return ref
			}
			match = true
			i++
		case asciiEqualFold(args[i], "count"):
			if count {
				return duplicate("COUNT")
			}
			if ref := needValue(args, i, "COUNT"); ref != nil {
				return ref
			}
			if ref := g.countOption(args[i+1]); ref != nil {
				return ref
			}
			count = true
			i++
		case extra == "type" && asciiEqualFold(args[i], "type"):
			if typ {
				return duplicate("TYPE")
			}
			if ref := needValue(args, i, "TYPE"); ref != nil {
				return ref
			}
			typ = true
			i++
		case extra == "novalues" && asciiEqualFold(args[i], "novalues"):
			if flag {
				return duplicate("NOVALUES")
			}
			flag = true
		default:
			return unknownArgument(offset + i)
		}
	}
	if !count {
		return missingCount(g)
	}
	return nil
}

func checkScan(g *Gate, args []string) *refusal {
	if len(args) < 1 {
		return refuse(ReasonWrongArity, "SCAN takes a cursor")
	}
	if !validCursor(args[0]) {
		return refuse(ReasonInvalidArgument, "the cursor must be an unsigned integer")
	}
	return scanOptions(g, args[1:], 1, "type")
}

func checkKeyScan(extra string) func(*Gate, []string) *refusal {
	return func(g *Gate, args []string) *refusal {
		if len(args) < 2 {
			return refuse(ReasonWrongArity, "the command takes a key and a cursor")
		}
		if !validCursor(args[1]) {
			return refuse(ReasonInvalidArgument, "the cursor must be an unsigned integer")
		}
		return scanOptions(g, args[2:], 2, extra)
	}
}

func checkMemoryUsage(g *Gate, args []string) *refusal {
	switch len(args) {
	case 1:
		return nil
	case 2, 3:
		if !asciiEqualFold(args[1], "samples") {
			return unknownArgument(1)
		}
		if len(args) == 2 {
			return refuse(ReasonWrongArity, "SAMPLES needs a value")
		}
		n, ref := intArg("SAMPLES", args[2])
		if ref != nil {
			return ref
		}
		if n < 0 {
			return refuse(ReasonInvalidArgument, "SAMPLES must not be negative")
		}
		if n == 0 || n > int64(g.limits.MaxElements) {
			return refuse(ReasonTooManyElements,
				"SAMPLES must be between 1 and "+itoa(g.limits.MaxElements)+"; SAMPLES 0 samples every element")
		}
		return nil
	default:
		return arityRange(args, 1, 3)
	}
}

func checkGetRange(_ *Gate, args []string) *refusal {
	if ref := arityRange(args, 3, 3); ref != nil {
		return ref
	}
	if _, ref := intArg("start", args[1]); ref != nil {
		return ref
	}
	_, ref := intArg("end", args[2])
	return ref
}

func checkGetBit(_ *Gate, args []string) *refusal {
	if ref := arityRange(args, 2, 2); ref != nil {
		return ref
	}
	n, ref := intArg("offset", args[1])
	if ref != nil {
		return ref
	}
	if n < 0 {
		return refuse(ReasonInvalidArgument, "offset must not be negative")
	}
	return nil
}

func bitUnit(s string, position int) *refusal {
	if asciiEqualFold(s, "byte") || asciiEqualFold(s, "bit") {
		return nil
	}
	return unknownArgument(position)
}

func checkBitCount(_ *Gate, args []string) *refusal {
	switch len(args) {
	case 1:
		return nil
	case 3, 4:
		if _, ref := intArg("start", args[1]); ref != nil {
			return ref
		}
		if _, ref := intArg("end", args[2]); ref != nil {
			return ref
		}
		if len(args) == 4 {
			return bitUnit(args[3], 3)
		}
		return nil
	case 2:
		return refuse(ReasonWrongArity, "start needs an end")
	default:
		return arityRange(args, 1, 4)
	}
}

func checkBitPos(_ *Gate, args []string) *refusal {
	if ref := arityRange(args, 2, 5); ref != nil {
		return ref
	}
	if args[1] != "0" && args[1] != "1" {
		return refuse(ReasonInvalidArgument, "bit must be 0 or 1")
	}
	if len(args) >= 3 {
		if _, ref := intArg("start", args[2]); ref != nil {
			return ref
		}
	}
	if len(args) >= 4 {
		if _, ref := intArg("end", args[3]); ref != nil {
			return ref
		}
	}
	if len(args) == 5 {
		return bitUnit(args[4], 4)
	}
	return nil
}

func checkRandom(flag string) func(*Gate, []string) *refusal {
	return func(g *Gate, args []string) *refusal {
		hi := 2
		if flag != "" {
			hi = 3
		}
		if ref := arityRange(args, 1, hi); ref != nil {
			return ref
		}
		if len(args) == 1 {
			return nil
		}
		n, ref := intArg("count", args[1])
		if ref != nil {
			return ref
		}
		limit := int64(g.limits.MaxElements)
		if n > limit || n < -limit {
			return refuse(ReasonTooManyElements, "count must be between -"+itoa(g.limits.MaxElements)+" and "+itoa(g.limits.MaxElements))
		}
		if len(args) == 3 && !asciiEqualFold(args[2], flag) {
			return unknownArgument(2)
		}
		return nil
	}
}

func checkLIndex(g *Gate, args []string) *refusal {
	if ref := arityRange(args, 2, 2); ref != nil {
		return ref
	}
	n, ref := intArg("index", args[1])
	if ref != nil {
		return ref
	}
	limit := int64(g.limits.MaxElements)
	if n >= limit || n < -limit {
		return refuse(ReasonTraversalTooDeep,
			"index must be between -"+itoa(g.limits.MaxElements)+" and "+itoa(g.limits.MaxElements-1)+
				"; LINDEX walks the list from the nearer end to index")
	}
	return nil
}

func checkLRange(g *Gate, args []string) *refusal {
	if ref := arityRange(args, 3, 3); ref != nil {
		return ref
	}
	if ref := g.window(args[1], args[2]); ref != nil {
		return ref
	}
	if stop, _ := parseInt(args[2]); stop >= int64(g.limits.MaxElements) {
		return refuse(ReasonTraversalTooDeep,
			"stop must be below "+itoa(g.limits.MaxElements)+"; LRANGE walks the list from its head to stop")
	}
	return nil
}

func checkLPos(g *Gate, args []string) *refusal {
	if len(args) < 2 {
		return refuse(ReasonWrongArity, "LPOS takes a key and an element")
	}
	var rank, count, maxlen bool
	for i := 2; i < len(args); i++ {
		switch {
		case asciiEqualFold(args[i], "rank"):
			if rank {
				return duplicate("RANK")
			}
			if ref := needValue(args, i, "RANK"); ref != nil {
				return ref
			}
			n, ref := intArg("RANK", args[i+1])
			if ref != nil {
				return ref
			}
			if n == 0 || n == -1<<63 {
				return refuse(ReasonInvalidArgument, "RANK must be a non-zero integer")
			}
			rank = true
			i++
		case asciiEqualFold(args[i], "count"):
			if count {
				return duplicate("COUNT")
			}
			if ref := needValue(args, i, "COUNT"); ref != nil {
				return ref
			}
			n, ref := intArg("COUNT", args[i+1])
			if ref != nil {
				return ref
			}
			if n < 0 {
				return refuse(ReasonInvalidArgument, "COUNT must not be negative")
			}
			if n > int64(g.limits.MaxCount) {
				return refuse(ReasonCountTooLarge, "COUNT must be at most "+itoa(g.limits.MaxCount))
			}
			count = true
			i++
		case asciiEqualFold(args[i], "maxlen"):
			if maxlen {
				return duplicate("MAXLEN")
			}
			if ref := needValue(args, i, "MAXLEN"); ref != nil {
				return ref
			}
			n, ref := intArg("MAXLEN", args[i+1])
			if ref != nil {
				return ref
			}
			if n < 0 {
				return refuse(ReasonInvalidArgument, "MAXLEN must not be negative")
			}
			if n == 0 || n > int64(g.limits.MaxElements) {
				return refuse(ReasonTooManyElements,
					"MAXLEN must be between 1 and "+itoa(g.limits.MaxElements)+"; MAXLEN 0 scans the whole list")
			}
			maxlen = true
			i++
		default:
			return unknownArgument(i)
		}
	}
	if !maxlen {
		return refuse(ReasonMissingMaxlen, "MAXLEN is required and must be between 1 and "+itoa(g.limits.MaxElements))
	}
	return nil
}

func checkZRank(_ *Gate, args []string) *refusal {
	if ref := arityRange(args, 2, 3); ref != nil {
		return ref
	}
	if len(args) == 3 && !asciiEqualFold(args[2], "withscore") {
		return unknownArgument(2)
	}
	return nil
}

func (g *Gate) limitOption(args []string, i int) *refusal {
	if i+2 >= len(args) {
		return refuse(ReasonWrongArity, "LIMIT needs an offset and a count")
	}
	offset, ref := intArg("LIMIT offset", args[i+1])
	if ref != nil {
		return ref
	}
	if offset < 0 {
		return refuse(ReasonInvalidArgument, "LIMIT offset must not be negative")
	}
	count, ref := intArg("LIMIT count", args[i+2])
	if ref != nil {
		return ref
	}
	if count < 0 || count > int64(g.limits.MaxElements) {
		return refuse(ReasonTooManyElements,
			"LIMIT count must be between 0 and "+itoa(g.limits.MaxElements)+"; a negative count returns every element in the range")
	}
	if offset > int64(g.limits.MaxElements)-count {
		return refuse(ReasonTraversalTooDeep,
			"LIMIT offset + count must be at most "+itoa(g.limits.MaxElements)+
				"; Redis walks past offset elements before it replies, so page by moving the min or max bound instead of offset")
	}
	return nil
}

func missingLimit(g *Gate) *refusal {
	return refuse(ReasonMissingLimit,
		"LIMIT offset count is required for a score or lex range, with offset + count at most "+itoa(g.limits.MaxElements))
}

func checkZRange(g *Gate, args []string) *refusal {
	if len(args) < 3 {
		return refuse(ReasonWrongArity, "ZRANGE takes a key, a start and a stop")
	}
	var byScore, byLex, rev, limit, withScores bool
	for i := 3; i < len(args); i++ {
		switch {
		case asciiEqualFold(args[i], "byscore"):
			if byScore {
				return duplicate("BYSCORE")
			}
			byScore = true
		case asciiEqualFold(args[i], "bylex"):
			if byLex {
				return duplicate("BYLEX")
			}
			byLex = true
		case asciiEqualFold(args[i], "rev"):
			if rev {
				return duplicate("REV")
			}
			rev = true
		case asciiEqualFold(args[i], "withscores"):
			if withScores {
				return duplicate("WITHSCORES")
			}
			withScores = true
		case asciiEqualFold(args[i], "limit"):
			if limit {
				return duplicate("LIMIT")
			}
			if ref := g.limitOption(args, i); ref != nil {
				return ref
			}
			limit = true
			i += 2
		default:
			return unknownArgument(i)
		}
	}
	switch {
	case byScore && byLex:
		return refuse(ReasonInvalidArgument, "BYSCORE and BYLEX cannot be combined")
	case byLex && withScores:
		return refuse(ReasonInvalidArgument, "WITHSCORES cannot be combined with BYLEX")
	case byScore || byLex:
		if !limit {
			return missingLimit(g)
		}
		return nil
	case limit:
		return refuse(ReasonInvalidArgument, "LIMIT is only accepted with BYSCORE or BYLEX")
	default:
		return g.window(args[1], args[2])
	}
}

func checkZRangeBy(scores bool) func(*Gate, []string) *refusal {
	return func(g *Gate, args []string) *refusal {
		if len(args) < 3 {
			return refuse(ReasonWrongArity, "the command takes a key, a min and a max")
		}
		var limit, withScores bool
		for i := 3; i < len(args); i++ {
			switch {
			case scores && asciiEqualFold(args[i], "withscores"):
				if withScores {
					return duplicate("WITHSCORES")
				}
				withScores = true
			case asciiEqualFold(args[i], "limit"):
				if limit {
					return duplicate("LIMIT")
				}
				if ref := g.limitOption(args, i); ref != nil {
					return ref
				}
				limit = true
				i += 2
			default:
				return unknownArgument(i)
			}
		}
		if !limit {
			return missingLimit(g)
		}
		return nil
	}
}

func checkZRevRange(g *Gate, args []string) *refusal {
	if ref := arityRange(args, 3, 4); ref != nil {
		return ref
	}
	if len(args) == 4 && !asciiEqualFold(args[3], "withscores") {
		return unknownArgument(3)
	}
	return g.window(args[1], args[2])
}

func checkXRange(g *Gate, args []string) *refusal {
	if len(args) < 3 {
		return refuse(ReasonWrongArity, "the command takes a key and two stream IDs")
	}
	var count bool
	for i := 3; i < len(args); i++ {
		if !asciiEqualFold(args[i], "count") {
			return unknownArgument(i)
		}
		if count {
			return duplicate("COUNT")
		}
		if ref := needValue(args, i, "COUNT"); ref != nil {
			return ref
		}
		if ref := g.countOption(args[i+1]); ref != nil {
			return ref
		}
		count = true
		i++
	}
	if !count {
		return missingCount(g)
	}
	return nil
}

func checkXInfoStream(g *Gate, args []string) *refusal {
	if len(args) < 1 {
		return refuse(ReasonWrongArity, "XINFO STREAM takes a key")
	}
	if len(args) == 1 {
		return nil
	}
	if !asciiEqualFold(args[1], "full") {
		return unknownArgument(1)
	}
	if len(args) == 2 {
		return missingCount(g)
	}
	if !asciiEqualFold(args[2], "count") {
		return unknownArgument(2)
	}
	if len(args) == 3 {
		return refuse(ReasonWrongArity, "COUNT needs a value")
	}
	if ref := g.countOption(args[3]); ref != nil {
		return ref
	}
	if len(args) > 4 {
		return unknownArgument(4)
	}
	return nil
}

func checkXPending(g *Gate, args []string) *refusal {
	if len(args) < 2 {
		return refuse(ReasonWrongArity, "XPENDING takes a key and a group")
	}
	rest := args[2:]
	if len(rest) == 0 {
		return nil
	}
	if asciiEqualFold(rest[0], "idle") {
		return refuse(ReasonTraversalTooDeep,
			"IDLE is not accepted; XPENDING skips entries younger than IDLE without counting them, so COUNT does not bound the walk")
	}
	switch len(rest) {
	case 1:
		return refuse(ReasonWrongArity, "the extended form takes a start, an end and a count")
	case 2:
		return missingCount(g)
	case 3, 4:
		return g.countOption(rest[2])
	default:
		return unknownArgument(6)
	}
}

func geoUnit(s string) bool {
	return asciiEqualFold(s, "m") || asciiEqualFold(s, "km") || asciiEqualFold(s, "ft") || asciiEqualFold(s, "mi")
}

func checkGeoDist(_ *Gate, args []string) *refusal {
	if ref := arityRange(args, 3, 4); ref != nil {
		return ref
	}
	if len(args) == 4 && !geoUnit(args[3]) {
		return unknownArgument(3)
	}
	return nil
}

func checkGeoSearch(g *Gate, args []string) *refusal {
	if len(args) < 1 {
		return refuse(ReasonWrongArity, "GEOSEARCH takes a key")
	}
	var from, by, order, count, coord, dist, hash bool
	for i := 1; i < len(args); i++ {
		switch {
		case asciiEqualFold(args[i], "frommember"):
			if from {
				return refuse(ReasonInvalidArgument, "exactly one of FROMMEMBER and FROMLONLAT is accepted")
			}
			if ref := needValue(args, i, "FROMMEMBER"); ref != nil {
				return ref
			}
			from = true
			i++
		case asciiEqualFold(args[i], "fromlonlat"):
			if from {
				return refuse(ReasonInvalidArgument, "exactly one of FROMMEMBER and FROMLONLAT is accepted")
			}
			if i+2 >= len(args) {
				return refuse(ReasonWrongArity, "FROMLONLAT needs a longitude and a latitude")
			}
			from = true
			i += 2
		case asciiEqualFold(args[i], "byradius"):
			if by {
				return refuse(ReasonInvalidArgument, "exactly one of BYRADIUS and BYBOX is accepted")
			}
			if i+2 >= len(args) {
				return refuse(ReasonWrongArity, "BYRADIUS needs a radius and a unit")
			}
			if !geoUnit(args[i+2]) {
				return unknownArgument(i + 2)
			}
			by = true
			i += 2
		case asciiEqualFold(args[i], "bybox"):
			if by {
				return refuse(ReasonInvalidArgument, "exactly one of BYRADIUS and BYBOX is accepted")
			}
			if i+3 >= len(args) {
				return refuse(ReasonWrongArity, "BYBOX needs a width, a height and a unit")
			}
			if !geoUnit(args[i+3]) {
				return unknownArgument(i + 3)
			}
			by = true
			i += 3
		case asciiEqualFold(args[i], "asc"), asciiEqualFold(args[i], "desc"):
			if order {
				return duplicate("ASC or DESC")
			}
			order = true
		case asciiEqualFold(args[i], "count"):
			if count {
				return duplicate("COUNT")
			}
			if ref := needValue(args, i, "COUNT"); ref != nil {
				return ref
			}
			if ref := g.countOption(args[i+1]); ref != nil {
				return ref
			}
			count = true
			i++
			if i+1 < len(args) && asciiEqualFold(args[i+1], "any") {
				i++
			}
		case asciiEqualFold(args[i], "withcoord"):
			if coord {
				return duplicate("WITHCOORD")
			}
			coord = true
		case asciiEqualFold(args[i], "withdist"):
			if dist {
				return duplicate("WITHDIST")
			}
			dist = true
		case asciiEqualFold(args[i], "withhash"):
			if hash {
				return duplicate("WITHHASH")
			}
			hash = true
		default:
			return unknownArgument(i)
		}
	}
	if !from {
		return refuse(ReasonInvalidArgument, "one of FROMMEMBER and FROMLONLAT is required")
	}
	if !by {
		return refuse(ReasonInvalidArgument, "one of BYRADIUS and BYBOX is required")
	}
	if !count {
		return missingCount(g)
	}
	return nil
}
