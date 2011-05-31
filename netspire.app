{application, netspire, [
    {description, "Billing system"},
    {vsn, "0.1"},
    {modules, [
        netspire,
        netspire_sup,
        netspire_netflow,
        netspire_radius
    ]},
    {registered, []},
    {applications, [kernel, stdlib]},
    {mod, {netspire, []}}
]}.
