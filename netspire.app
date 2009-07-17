{application, netspire,
    [{description, "Distributed system for collecting, accounting and processing network flows."},
     {vsn, "0.1"},
     {modules, [netspire,
                netspire_sup,
                netspire_netflow,
                netspire_radius
               ]},
    {registered, []},
    {applications, [kernel, stdlib]},
    {mod, {netspire_app, []}}
]}.
