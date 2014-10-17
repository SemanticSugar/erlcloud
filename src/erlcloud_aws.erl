-module(erlcloud_aws).
-export([aws_request/6, aws_request_xml/6,
         param_list/2, default_config/0, establish_config/1, establish_config/2,
         format_timestamp/1]).

-include_lib("erlcloud/include/erlcloud_aws.hrl").

-define(METADATA_REQUEST_NUM_RETRIES, 2).
-define(METADATA_REQUEST_TIMEOUT, 1000).
-define(METADATA_REQUEST_CONNECTION_TIMEOUT, 1000).


aws_request_xml(Method, Host, Path, Params, AccessKeyID, SecretAccessKey) ->
    Body = aws_request(Method, Host, Path, Params, AccessKeyID, SecretAccessKey),
    %io:format("Body = ~p~n", [Body]),
    element(1, xmerl_scan:string(Body)).

aws_request(Method, Host, Path, Params, AccessKeyID, SecretAccessKey) ->
    Timestamp = format_timestamp(erlang:universaltime()),
    QParams = lists:sort([{"Timestamp", Timestamp},
                          {"SignatureVersion", "2"},
                          {"SignatureMethod", "HmacSHA1"},
                          {"AWSAccessKeyId", AccessKeyID}|Params]),

    QueryToSign = erlcloud_http:make_query_string(QParams),
    RequestToSign = [string:to_upper(atom_to_list(Method)), $\n,
                     string:to_lower(Host), $\n, Path, $\n, QueryToSign],
    Signature = base64:encode(crypto:sha_mac(SecretAccessKey, RequestToSign)),

    Query = [QueryToSign, "&Signature=", erlcloud_http:url_encode(Signature)],

    URL = ["https://", Host, Path],

    Response =
        case Method of
            get ->
                Req = lists:flatten([URL, $?, Query]),
                %io:format("Req: >~s<~n", [Req]),
                httpc:request(Req);
            _ ->
                httpc:request(Method,
                             {lists:flatten(URL), [], "application/x-www-form-urlencoded",
                              list_to_binary(Query)}, [], [])
        end,

    case Response of
        {ok, {{_HTTPVer, 200, _StatusLine}, _Headers, Body}} ->
            Body;
        {ok, {{_HTTPVer, Status, _StatusLine}, _Headers, _Body}} ->
            erlang:error({aws_error, {http_error, Status, _StatusLine, _Body}});
        {error, Error} ->
            erlang:error({aws_error, {socket_error, Error}})
    end.

param_list([], _Key) -> [];
param_list(Values, Key) when is_tuple(Key) ->
    Seq = lists:seq(1, size(Key)),
    lists:flatten(
        [[{lists:append([element(J, Key), ".", integer_to_list(I)]),
           element(J, Value)} || J <- Seq] ||
         {I, Value} <- lists:zip(lists:seq(1, length(Values)), Values)]
    );
param_list([[{_, _}|_]|_] = Values, Key) ->
    lists:flatten(
        [[{lists:flatten([Key, $., integer_to_list(I), $., SubKey]),
           value_to_string(Value)} || {SubKey, Value} <- SValues] ||
         {I, SValues} <- lists:zip(lists:seq(1, length(Values)), Values)]
    );
param_list(Values, Key) ->
    [{lists:flatten([Key, $., integer_to_list(I)]), Value} ||
     {I, Value} <- lists:zip(lists:seq(1, length(Values)), Values)].

value_to_string(Integer) when is_integer(Integer) -> integer_to_list(Integer);
value_to_string(Atom) when is_atom(Atom) -> atom_to_list(Atom);
value_to_string(Binary) when is_binary(Binary) -> Binary;
value_to_string(String) when is_list(String) -> String;
value_to_string({{_Yr, _Mo, _Da}, {_Hr, _Min, _Sec}} = Timestamp) -> format_timestamp(Timestamp).

format_timestamp({{Yr, Mo, Da}, {H, M, S}}) ->
    lists:flatten(
        io_lib:format("~4.10.0b-~2.10.0b-~2.10.0bT~2.10.0b:~2.10.0b:~2.10.0bZ",
                      [Yr, Mo, Da, H, M, S])).



default_config() ->
    establish_config([], false).


establish_config(ConfigParams) ->
    establish_config(ConfigParams, true).
establish_config(ConfigParams, Cache) ->
    case get(aws_config) of
        undefined ->
            case {infer_config(ConfigParams), Cache} of
                {Config = #aws_config{}, true} ->
                    put(aws_config, Config),
                    Config;
                {Result, _} ->
                    Result
            end;
        CachedConfig ->
            CachedConfig
    end.

infer_config(ConfigParams) ->
    ConfigWithKeys = case config_keys_from_env() of
                         error ->
                             config_keys_from_metadata();
                         AwsConfig = #aws_config{} ->
                             AwsConfig
                     end,

    ConfigWithKeys#aws_config{
        ec2_host = proplists:get_value(ec2_host, ConfigParams, ConfigWithKeys#aws_config.ec2_host),
        s3_host = proplists:get_value(s3_host, ConfigParams, ConfigWithKeys#aws_config.s3_host),
        s3_port = proplists:get_value(s3_port, ConfigParams, ConfigWithKeys#aws_config.s3_port),
        sdb_host = proplists:get_value(sdb_host, ConfigParams, ConfigWithKeys#aws_config.sdb_host),
        elb_host = proplists:get_value(elb_host, ConfigParams, ConfigWithKeys#aws_config.elb_host),
        sqs_host = proplists:get_value(sqs_host, ConfigParams, ConfigWithKeys#aws_config.sqs_host),
        mturk_host = proplists:get_value(mturk_host, ConfigParams,ConfigWithKeys#aws_config.mturk_host),
        mon_host = proplists:get_value(mon_host, ConfigParams, ConfigWithKeys#aws_config.mon_host)
    }.

config_keys_from_env() ->
    case {os:getenv("AWS_ACCESS_KEY_ID"), os:getenv("AWS_SECRET_ACCESS_KEY")} of
        {false, _} ->
            error;
        {_, false} ->
            error;
        {AccessKeyId, SecretAccessKey} ->
            #aws_config{access_key_id=AccessKeyId, secret_access_key=SecretAccessKey}
    end.

config_keys_from_metadata() ->
    {ok, InstanceProfile} = metadata_request("iam/security-credentials/"),
    {ok, SecurityCreds} = metadata_request("iam/security-credentials/" ++ InstanceProfile),
    {SecurityCredsParams} = jiffy:decode(SecurityCreds),
    AccessKeyId = proplists:get_value(<<"AccessKeyId">>, SecurityCredsParams),
    SecretAccessKey = proplists:get_value(<<"SecretAccessKey">>, SecurityCredsParams),
    case {AccessKeyId, SecretAccessKey} of
        {undefined, _} ->
            error_logger:error_msg("Error fetching aws metadata configuration: ~p, access key id came back empty."),
            error;
        {_, undefined} ->
            error_logger:error_msg("Error fetching aws metadata configuration: ~p, secret access key came back empty."),
            error;
        _ ->
            #aws_config{access_key_id=AccessKeyId, secret_access_key=SecretAccessKey}
    end.

metadata_request(RequestSuffix) ->
    metadata_request(RequestSuffix, ?METADATA_REQUEST_NUM_RETRIES).

metadata_request(_RequestSuffix, 0) ->
    error;
metadata_request(RequestSuffix, Tries) ->
    case httpc:request(get,
        {"http://169.254.169.254/latest/meta-data/" ++ RequestSuffix, []},
        [{timeout, ?METADATA_REQUEST_TIMEOUT},
            {connect_timeout, ?METADATA_REQUEST_CONNECTION_TIMEOUT}],
        []) of
        {ok, {{_, 200, _}, _Headers, Body}} ->
            {ok, Body};
        {ok, {{_, StatusCode, _}, _Headers, _Body}} ->
            error_logger:error_msg("Error fetching aws metadata configuration: ~p, status code: ~p",
                [RequestSuffix, StatusCode]),
            metadata_request(RequestSuffix, Tries-1);
        {error, Reason} ->
            error_logger:error_msg("Error fetching aws metadata configuration: ~p, reason: ~p",
                [RequestSuffix, Reason]),
            metadata_request(RequestSuffix, Tries-1)
    end.
