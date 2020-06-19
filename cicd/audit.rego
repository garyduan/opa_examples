package psp

default allow = false

allow = true {
	count(input.report.vulnerabilities) < 3
}




