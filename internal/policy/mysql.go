package policy

import "strings"

func validateMySQLRead(words []shellWord) bool {
	query, ok := directMySQLQuery(words)
	return ok && validateReadOnlySQL(query)
}

// validateMySQLSelect preserves the narrower behavior of existing external
// policies that already refer to the original validator name.
func validateMySQLSelect(words []shellWord) bool {
	query, ok := directMySQLQuery(words)
	return ok && validateSelectSQL(query)
}

func directMySQLQuery(words []shellWord) (string, bool) {
	if len(words) != 7 ||
		words[0].value != "/usr/bin/mysql" ||
		words[1].value != "--defaults-file=/root/.my.cnf" ||
		words[2].value != "-N" ||
		words[3].value != "--batch" ||
		!allowedVoiceDatabase(words[4].value) ||
		words[5].value != "-e" {
		return "", false
	}
	query := words[6]
	if (query.quote != '"' && query.quote != '\'') || query.mixed {
		return "", false
	}
	return query.value, true
}

func validateMySQLShellRead(words []shellWord) bool {
	if len(words) != 9 ||
		words[0].value != "runagent" || words[1].value != "-m" ||
		!cleanLiteral(words[2].value) || words[3].value != "podman" ||
		words[4].value != "exec" || words[5].value != "mariadb" ||
		words[6].value != "sh" || words[7].value != "-c" ||
		words[8].quote != '\'' || words[8].mixed {
		return false
	}
	const prefix = `mysql -uroot -p${MARIADB_ROOT_PASSWORD} -N -B `
	command := words[8].value
	if !strings.HasPrefix(command, prefix) {
		return false
	}
	command = strings.TrimPrefix(command, prefix)
	database, command, found := strings.Cut(command, " -e ")
	if !found || !allowedVoiceDatabase(database) {
		return false
	}
	query, ok := quotedShellQuery(command)
	return ok && validateReadOnlySQL(query)
}

func quotedShellQuery(value string) (string, bool) {
	if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
		return value[1 : len(value)-1], true
	}
	if len(value) >= 4 && strings.HasPrefix(value, `\"`) && strings.HasSuffix(value, `\"`) {
		return value[2 : len(value)-2], true
	}
	return "", false
}

func allowedVoiceDatabase(value string) bool {
	return value == "asterisk" || value == "asteriskcdrdb"
}

func validateReadOnlySQL(query string) bool {
	tokens, ok := scanSQL(query)
	if !ok {
		return false
	}
	parser := sqlParser{tokens: tokens}
	return parser.readStatement() && parser.atEnd()
}

func validateSelectSQL(query string) bool {
	tokens, ok := scanSQL(query)
	if !ok {
		return false
	}
	parser := sqlParser{tokens: tokens}
	return parser.selectStatement() && parser.atEnd()
}

type sqlTokenKind uint8

const (
	sqlIdentifier sqlTokenKind = iota
	sqlNumber
	sqlString
	sqlComma
	sqlLeftParen
	sqlRightParen
	sqlStar
	sqlDot
	sqlComparison
	sqlPattern
)

type sqlToken struct {
	kind  sqlTokenKind
	value string
}

func scanSQL(query string) ([]sqlToken, bool) {
	var result []sqlToken
	for index := 0; index < len(query); {
		character := query[index]
		if character == ' ' || character == '\t' || character == '\n' || character == '\r' {
			index++
			continue
		}
		if asciiLetter(character) || character == '_' {
			start := index
			index++
			for index < len(query) && (asciiLetter(query[index]) || asciiDigit(query[index]) || query[index] == '_') {
				index++
			}
			result = append(result, sqlToken{kind: sqlIdentifier, value: query[start:index]})
			continue
		}
		if asciiDigit(character) {
			start := index
			for index < len(query) && asciiDigit(query[index]) {
				index++
			}
			if index < len(query) && query[index] == '.' {
				index++
				decimalStart := index
				for index < len(query) && asciiDigit(query[index]) {
					index++
				}
				if decimalStart == index {
					return nil, false
				}
			}
			result = append(result, sqlToken{kind: sqlNumber, value: query[start:index]})
			continue
		}
		switch character {
		case '\'':
			index++
			var literal strings.Builder
			closed := false
			for index < len(query) {
				if query[index] == '\\' {
					return nil, false
				}
				if query[index] == '\'' {
					if index+1 < len(query) && query[index+1] == '\'' {
						literal.WriteByte('\'')
						index += 2
						continue
					}
					index++
					closed = true
					break
				}
				literal.WriteByte(query[index])
				index++
			}
			if !closed {
				return nil, false
			}
			result = append(result, sqlToken{kind: sqlString, value: literal.String()})
		case ',':
			result = append(result, sqlToken{kind: sqlComma, value: ","})
			index++
		case '(':
			result = append(result, sqlToken{kind: sqlLeftParen, value: "("})
			index++
		case ')':
			result = append(result, sqlToken{kind: sqlRightParen, value: ")"})
			index++
		case '*':
			result = append(result, sqlToken{kind: sqlStar, value: "*"})
			index++
		case '.':
			result = append(result, sqlToken{kind: sqlDot, value: "."})
			index++
		case '=', '<', '>', '!':
			start := index
			index++
			if index < len(query) && (query[index] == '=' || (character == '<' && query[index] == '>')) {
				index++
			}
			operator := query[start:index]
			if operator == "!" || operator == "==" || operator == ">>" || operator == "!!" {
				return nil, false
			}
			result = append(result, sqlToken{kind: sqlComparison, value: operator})
		case '%':
			start := index
			for index < len(query) && (query[index] == '%' || query[index] == '_' || asciiLetter(query[index]) || asciiDigit(query[index])) {
				index++
			}
			result = append(result, sqlToken{kind: sqlPattern, value: query[start:index]})
		default:
			// This excludes statement terminators, comments, variables,
			// identifier quotes, arithmetic, and client metacommands.
			return nil, false
		}
	}
	return result, len(result) > 0
}

type sqlParser struct {
	tokens []sqlToken
	index  int
}

func (p *sqlParser) readStatement() bool {
	if p.index >= len(p.tokens) || p.tokens[p.index].kind != sqlIdentifier {
		return false
	}
	switch strings.ToUpper(p.tokens[p.index].value) {
	case "SELECT":
		return p.selectStatement()
	case "SHOW":
		return p.showStatement()
	case "DESCRIBE", "DESC":
		return p.describeStatement()
	default:
		return false
	}
}

func (p *sqlParser) showStatement() bool {
	if !p.keyword("SHOW") {
		return false
	}
	if p.keyword("TABLES") {
		if p.keyword("LIKE") {
			return p.showPattern()
		}
		return true
	}
	if p.keyword("COLUMNS") || p.keyword("FIELDS") {
		if !(p.keyword("FROM") || p.keyword("IN")) || !p.identifier() {
			return false
		}
		if p.keyword("LIKE") {
			return p.showPattern()
		}
		return true
	}
	if p.keyword("INDEX") || p.keyword("INDEXES") || p.keyword("KEYS") {
		return (p.keyword("FROM") || p.keyword("IN")) && p.identifier()
	}
	if p.keyword("CREATE") {
		return (p.keyword("TABLE") || p.keyword("VIEW")) && p.identifier()
	}
	return false
}

func (p *sqlParser) describeStatement() bool {
	if !(p.keyword("DESCRIBE") || p.keyword("DESC")) || !p.identifier() {
		return false
	}
	if p.currentKind(sqlIdentifier) {
		return p.identifier()
	}
	return p.kind(sqlString) || p.kind(sqlPattern) || p.atEnd()
}

func (p *sqlParser) showPattern() bool {
	return p.kind(sqlString) || p.kind(sqlPattern)
}

func (p *sqlParser) selectStatement() bool {
	if !p.keyword("SELECT") || !p.selectList() || !p.keyword("FROM") || !p.identifier() {
		return false
	}
	if p.keyword("WHERE") && !p.booleanExpression() {
		return false
	}
	if p.keyword("ORDER") {
		if !p.keyword("BY") || !p.orderList() {
			return false
		}
	}
	if p.keyword("LIMIT") && !p.limit() {
		return false
	}
	return true
}

func (p *sqlParser) selectList() bool {
	if p.kind(sqlStar) {
		return true
	}
	if !p.selectExpression() {
		return false
	}
	for p.kind(sqlComma) {
		if !p.selectExpression() {
			return false
		}
	}
	return true
}

func (p *sqlParser) selectExpression() bool {
	if !p.scalar(false) {
		return false
	}
	if p.keyword("AS") {
		return p.identifier()
	}
	return true
}

func (p *sqlParser) booleanExpression() bool {
	if !p.booleanTerm() {
		return false
	}
	for p.keyword("AND") || p.keyword("OR") {
		if !p.booleanTerm() {
			return false
		}
	}
	return true
}

func (p *sqlParser) booleanTerm() bool {
	if p.kind(sqlLeftParen) {
		return p.booleanExpression() && p.kind(sqlRightParen)
	}
	if !p.scalar(true) {
		return false
	}
	if p.kind(sqlComparison) || p.keyword("LIKE") {
		return p.scalar(true)
	}
	if p.keyword("IS") {
		_ = p.keyword("NOT")
		return p.keyword("NULL")
	}
	return false
}

func (p *sqlParser) orderList() bool {
	if !p.scalar(false) {
		return false
	}
	p.orderDirection()
	for p.kind(sqlComma) {
		if !p.scalar(false) {
			return false
		}
		p.orderDirection()
	}
	return true
}

func (p *sqlParser) orderDirection() {
	if p.keyword("ASC") {
		return
	}
	_ = p.keyword("DESC")
}

func (p *sqlParser) limit() bool {
	if !p.currentKind(sqlNumber) || strings.Contains(p.tokens[p.index].value, ".") || !decimal(p.tokens[p.index].value, true) {
		return false
	}
	firstPositive := decimal(p.tokens[p.index].value, false)
	p.index++
	if p.kind(sqlComma) {
		return p.positiveInteger()
	}
	if !firstPositive {
		return false
	}
	if p.keyword("OFFSET") {
		return p.nonnegativeInteger()
	}
	return true
}

func (p *sqlParser) scalar(allowLiteral bool) bool {
	if p.currentKind(sqlIdentifier) {
		name := p.tokens[p.index].value
		p.index++
		if p.kind(sqlLeftParen) {
			switch strings.ToUpper(name) {
			case "UPPER", "LOWER":
				return p.scalar(true) && p.kind(sqlRightParen)
			case "REPLACE":
				return p.scalar(true) && p.kind(sqlComma) && p.scalar(true) && p.kind(sqlComma) && p.scalar(true) && p.kind(sqlRightParen)
			default:
				return false
			}
		}
		if reservedSQLWord(name) {
			return false
		}
		if p.kind(sqlDot) {
			return p.identifier()
		}
		return true
	}
	if allowLiteral && (p.kind(sqlString) || p.kind(sqlNumber) || p.keyword("NULL") || p.keyword("TRUE") || p.keyword("FALSE")) {
		return true
	}
	return false
}

func (p *sqlParser) identifier() bool {
	if !p.currentKind(sqlIdentifier) || reservedSQLWord(p.tokens[p.index].value) {
		return false
	}
	p.index++
	return true
}

func (p *sqlParser) positiveInteger() bool {
	if !p.currentKind(sqlNumber) || strings.Contains(p.tokens[p.index].value, ".") || !decimal(p.tokens[p.index].value, false) {
		return false
	}
	p.index++
	return true
}

func (p *sqlParser) nonnegativeInteger() bool {
	if !p.currentKind(sqlNumber) || strings.Contains(p.tokens[p.index].value, ".") || !decimal(p.tokens[p.index].value, true) {
		return false
	}
	p.index++
	return true
}

func (p *sqlParser) keyword(value string) bool {
	if !p.currentKind(sqlIdentifier) || !strings.EqualFold(p.tokens[p.index].value, value) {
		return false
	}
	p.index++
	return true
}

func (p *sqlParser) kind(kind sqlTokenKind) bool {
	if !p.currentKind(kind) {
		return false
	}
	p.index++
	return true
}

func (p *sqlParser) currentKind(kind sqlTokenKind) bool {
	return p.index < len(p.tokens) && p.tokens[p.index].kind == kind
}

func (p *sqlParser) atEnd() bool { return p.index == len(p.tokens) }

func reservedSQLWord(value string) bool {
	switch strings.ToUpper(value) {
	case "SELECT", "FROM", "WHERE", "ORDER", "BY", "LIMIT", "OFFSET",
		"AND", "OR", "AS", "ASC", "DESC", "LIKE", "IS", "NOT", "NULL",
		"TRUE", "FALSE", "JOIN", "INNER", "LEFT", "RIGHT", "CROSS", "ON",
		"UNION", "INTO", "OUTFILE", "DUMPFILE", "FOR", "LOCK", "PROCEDURE",
		"SHOW", "TABLES", "COLUMNS", "FIELDS", "INDEX", "INDEXES", "KEYS",
		"CREATE", "TABLE", "VIEW", "DESCRIBE", "IN":
		return true
	default:
		return false
	}
}

func asciiLetter(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z'
}

func asciiDigit(value byte) bool { return value >= '0' && value <= '9' }
