package policy

default allow = false

allow = true {
    data.kind = "NetworkPolicy"
    data.metadata.namespace = "demo"
    ingress_port
    egress_exist
}

ingress_port = true {
    count(data.spec.ingress[0].ports) <= 1
}

ingress_port = true {
    not data.spec.ingress[0].ports
}

egress_exist = true {
    e := data.spec.egress[_]
    e.to[0].podSelector
}

egress_exist = true {
    e := data.spec.egress[_]
    e.to[0].namespaceSelector
}


