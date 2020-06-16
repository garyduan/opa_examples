package crd

default allow = false

allow = true {
    # target of the network policy
    some r1
    target := data.items[r1].spec.target
    target.selector.criteria[0].key = "address"
    target.selector.criteria[0].op = "="
    target.selector.criteria[0].value = "oracledb.acme.com"

    # ingress L7 application rule to the target
    some j
    ingress := data.items[r1].spec.ingress[j]
    ingress.applications[_] = "Oracle"
    ingress.selector.criteria[0].key = "service"
    ingress.selector.criteria[0].op = "="
    startswith(ingress.selector.criteria[0].value, "myapp-pod")

    # only 'allow' rules are needed, network rules are implicit deny
    ingress.action = "allow"

    # cluster level process rule that prevents ssh daemon
    # from running in the containers
    some r2
    t := data.items[r2].spec.target
    t.selector.criteria[0].key = "container"
    t.selector.criteria[0].op = "="
    t.selector.criteria[0].value = "*"

    some p
    data.items[r2].spec.process[p].action = "deny"
    data.items[r2].spec.process[p].name = "sshd"
}


