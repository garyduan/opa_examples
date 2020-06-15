package admission

default allow = false

allow = true {
    some i
    r := input.rules[i]
    r.disable = false
    r.rule_type = "deny"

    some c1
    r.criteria[c1].name = "namespace"
    r.criteria[c1].op = "notContainsAny"
    r.criteria[c1].value = "staging"

    some c2
    r.criteria[c2].name = "cveHighWithFixCount"
    r.criteria[c2].op = ">="
    r.criteria[c2].value = "5"

    some c2s
    r.criteria[c2].sub_criteria[c2s].name = "publishDays"
    r.criteria[c2].sub_criteria[c2s].op = ">="
    r.criteria[c2].sub_criteria[c2s].value = "30"
}