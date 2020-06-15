package psp

import data.roles.bindings as bindings
import data.roles.permissions as role

default allow = false

allow = true {
    some spec
    profile[spec]
    spec.privileged = false
}

allow = true {
    some spec
    profile[spec]
    spec.privileged != false
    input.ServiceAccount.namespace = "admin"
}

profile[spec] {
    some i
    spec := data.spec

    bindings.subjects[i].namespace = input.ServiceAccount.namespace
    bindings.subjects[i].name = input.ServiceAccount.name

    role.metadata.name = bindings.roleRef.name

    data.metadata.name = role.rules[_].resourceNames[_]
}
