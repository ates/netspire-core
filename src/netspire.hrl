%% Print in standard output
-define(PRINT(Format, Args), io:format(Format, Args)).

%%
%% Logging
%%

-define(INFO_MSG(Format, Args),
    error_logger:info_msg(Format, Args)).

-define(WARNING_MSG(Format, Args),
    error_logger:warning_msg(Format, Args)).

-define(ERROR_MSG(Format, Args),
    error_logger:error_msg(Format, Args)).
