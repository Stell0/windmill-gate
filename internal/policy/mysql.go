package policy

import "strings"

func validateMySQLSelect(words []shellWord) bool {
	if len(words) != 7 ||
		words[0].value != "/usr/bin/mysql" ||
		words[1].value != "--defaults-file=/root/.my.cnf" ||
		words[2].value != "-N" ||
		words[3].value != "--batch" ||
		words[4].value != "asterisk" ||
		words[5].value != "-e" {
		return false
	}
	query := words[6]
	if query.quote != '"' || query.mixed {
		return false
	}
	tokens, ok := scanSQL(query.value)
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
		"UNION", "INTO", "OUTFILE", "DUMPFILE", "FOR", "LOCK", "PROCEDURE":
		return true
	default:
		return false
	}
}

func asciiLetter(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z'
}

func asciiDigit(value byte) bool { return value >= '0' && value <= '9' }
