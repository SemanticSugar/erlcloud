%% @author Ransom Richardson <ransom@ransomr.net>
%% @doc
%%
%% HTTP client abstraction for erlcloud. Simplifies changing http clients.
%% API matches lhttpc, except Config is passed instead of options for
%% future cusomizability.
%%
%% @end

-module(erlcloud_httpc).

-export([request/5, request/7]).

request(URL, Method, Hdrs, Timeout, _Config) ->
    httpc:request(Method, {URL, Hdrs},
        [{timeout, Timeout}, {connect_timeout, Timeout}],
        []).

request(URL, Method, Hdrs, ContentType, Body, Timeout, _Config) ->
    httpc:request(Method, {URL, Hdrs, ContentType, Body},
        [{timeout, Timeout}, {connect_timeout, Timeout}],
        []).
