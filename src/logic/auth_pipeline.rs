use crate::{
    config::{AuthPipeline, AuthRule},
    providers::{AuthContextHeaders, AuthProviders},
};

pub(crate) fn get_pipeline_for_request<'a>(
    headers: &AuthContextHeaders,
    auth_providers: &'a AuthProviders,
) -> Option<&'a AuthPipeline> {
    auth_providers
        .pipelines()
        .into_iter()
        .find(|f| matches_rules(headers, &f.rules))
}

#[inline]
fn matches_rules(headers: &AuthContextHeaders, rules: &Vec<AuthRule>) -> bool {
    rules
        .iter()
        .map(|rule| matches_rule(headers, rule))
        .reduce(|a, b| a && b)
        .unwrap_or(true)
}

fn matches_rule(headers: &AuthContextHeaders, rule: &AuthRule) -> bool {
    match rule {
        // TODO regex?
        AuthRule::HttpHost(host) => headers
            .x_forwarded_host
            .as_ref()
            .map_or(false, |h| h.eq_ignore_ascii_case(host)),
        AuthRule::HttpMethod(methods) => headers.x_forwarded_method.as_ref().map_or(false, |m| {
            methods.iter().any(|method| m.eq_ignore_ascii_case(method))
        }),
        AuthRule::HttpPath(path) => headers
            .x_forwarded_uri
            .as_ref()
            .map_or(false, |p| p == path),
        AuthRule::HttpPathPrefix(path_prefix) => headers
            .x_forwarded_uri
            .as_ref()
            .map_or(false, |p| p.starts_with(path_prefix)),
        AuthRule::HttpProtocol(protocol) => headers
            .x_forwarded_proto
            .as_ref()
            .map_or(false, |p| p.eq_ignore_ascii_case(protocol)),
        AuthRule::Or(sub_rules) => sub_rules
            .iter()
            .map(|sr| matches_rule(headers, sr))
            .reduce(|a, b| a || b)
            .unwrap_or(false),
        AuthRule::And(sub_rules) => sub_rules
            .iter()
            .map(|sr| matches_rule(headers, sr))
            .reduce(|a, b| a && b)
            .unwrap_or(true),
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn host_rule_matches() {
        let headers = AuthContextHeaders {
            authorization: None,
            x_forwarded_host: Some("example.com".into()),
            x_forwarded_method: None,
            x_forwarded_proto: None,
            x_forwarded_uri: None,
        };
        let result = matches_rule(&headers, &AuthRule::HttpHost("example.com".into()));
        assert_eq!(result, true);
    }

    #[test]
    fn host_rule_does_not_match() {
        let headers = AuthContextHeaders {
            authorization: None,
            x_forwarded_host: Some("google.com".into()),
            x_forwarded_method: None,
            x_forwarded_proto: None,
            x_forwarded_uri: None,
        };
        let result = matches_rule(&headers, &AuthRule::HttpHost("example.com".into()));
        assert_eq!(result, false);
    }

    #[test]
    fn method_rule_matches() {
        let headers = AuthContextHeaders {
            authorization: None,
            x_forwarded_host: None,
            x_forwarded_method: Some("GET".into()),
            x_forwarded_proto: None,
            x_forwarded_uri: None,
        };
        let result = matches_rule(
            &headers,
            &AuthRule::HttpMethod(vec!["post".into(), "get".into()]),
        );
        assert_eq!(result, true);
    }

    #[test]
    fn method_rule_does_not_match() {
        let headers = AuthContextHeaders {
            authorization: None,
            x_forwarded_host: None,
            x_forwarded_method: Some("GET".into()),
            x_forwarded_proto: None,
            x_forwarded_uri: None,
        };
        let result = matches_rule(&headers, &AuthRule::HttpMethod(vec!["post".into()]));
        assert_eq!(result, false);
    }

    #[test]
    fn path_rule_matches() {
        let headers = AuthContextHeaders {
            authorization: None,
            x_forwarded_host: None,
            x_forwarded_method: None,
            x_forwarded_proto: None,
            x_forwarded_uri: Some("/path".into()),
        };
        let result = matches_rule(&headers, &AuthRule::HttpPath("/path".into()));
        assert_eq!(result, true);
    }

    #[test]
    fn path_rule_does_not_match() {
        let headers = AuthContextHeaders {
            authorization: None,
            x_forwarded_host: None,
            x_forwarded_method: None,
            x_forwarded_proto: None,
            x_forwarded_uri: Some("/path".into()),
        };
        let result = matches_rule(&headers, &AuthRule::HttpPath("/other-path".into()));
        assert_eq!(result, false);
        let result = matches_rule(&headers, &AuthRule::HttpPath("/pa".into()));
        assert_eq!(result, false);
    }

    #[test]
    fn path_prefix_rule_matches() {
        let headers = AuthContextHeaders {
            authorization: None,
            x_forwarded_host: None,
            x_forwarded_method: None,
            x_forwarded_proto: None,
            x_forwarded_uri: Some("/some/path".into()),
        };
        let result = matches_rule(&headers, &AuthRule::HttpPathPrefix("/some".into()));
        assert_eq!(result, true);
        let result = matches_rule(&headers, &AuthRule::HttpPathPrefix("/some/path".into()));
        assert_eq!(result, true);
    }

    #[test]
    fn path_prefix_rule_does_not_match() {
        let headers = AuthContextHeaders {
            authorization: None,
            x_forwarded_host: None,
            x_forwarded_method: None,
            x_forwarded_proto: None,
            x_forwarded_uri: Some("/some/path".into()),
        };
        let result = matches_rule(&headers, &AuthRule::HttpPathPrefix("/another".into()));
        assert_eq!(result, false);
        let result = matches_rule(
            &headers,
            &AuthRule::HttpPathPrefix("/some/path/inside".into()),
        );
        assert_eq!(result, false);
    }

    #[test]
    fn protocol_rule_matches() {
        let headers = AuthContextHeaders {
            authorization: None,
            x_forwarded_host: None,
            x_forwarded_method: None,
            x_forwarded_proto: Some("https".into()),
            x_forwarded_uri: None,
        };
        let result = matches_rule(&headers, &AuthRule::HttpProtocol("HTTPS".into()));
        assert_eq!(result, true);
    }

    #[test]
    fn protocol_rule_does_not_match() {
        let headers = AuthContextHeaders {
            authorization: None,
            x_forwarded_host: None,
            x_forwarded_method: None,
            x_forwarded_proto: Some("https".into()),
            x_forwarded_uri: None,
        };
        let result = matches_rule(&headers, &AuthRule::HttpProtocol("HTTP".into()));
        assert_eq!(result, false);
    }

    #[test]
    fn or_rule_matches_first() {
        let headers = AuthContextHeaders {
            authorization: None,
            x_forwarded_host: None,
            x_forwarded_method: None,
            x_forwarded_proto: Some("https".into()),
            x_forwarded_uri: None,
        };
        let result = matches_rule(
            &headers,
            &AuthRule::Or(vec![
                AuthRule::HttpProtocol("HTTPS".into()),
                AuthRule::HttpProtocol("HTTP".into()),
            ]),
        );
        assert_eq!(result, true);
    }

    #[test]
    fn or_rule_matches_second() {
        let headers = AuthContextHeaders {
            authorization: None,
            x_forwarded_host: None,
            x_forwarded_method: None,
            x_forwarded_proto: Some("https".into()),
            x_forwarded_uri: None,
        };
        let result = matches_rule(
            &headers,
            &AuthRule::Or(vec![
                AuthRule::HttpProtocol("HTTP".into()),
                AuthRule::HttpProtocol("HTTPS".into()),
            ]),
        );
        assert_eq!(result, true);
    }

    #[test]
    fn or_rule_does_not_match() {
        let headers = AuthContextHeaders {
            authorization: None,
            x_forwarded_host: None,
            x_forwarded_method: None,
            x_forwarded_proto: None,
            x_forwarded_uri: None,
        };
        let result = matches_rule(
            &headers,
            &AuthRule::Or(vec![
                AuthRule::HttpProtocol("HTTP".into()),
                AuthRule::HttpProtocol("HTTPS".into()),
            ]),
        );
        assert_eq!(result, false);
    }

    #[test]
    fn or_rule_empty_does_not_match() {
        let headers = AuthContextHeaders {
            authorization: None,
            x_forwarded_host: None,
            x_forwarded_method: None,
            x_forwarded_proto: None,
            x_forwarded_uri: None,
        };
        let result = matches_rule(&headers, &AuthRule::Or(vec![]));
        assert_eq!(result, false);
    }

    #[test]
    fn and_rule_matches_first() {
        let headers = AuthContextHeaders {
            authorization: None,
            x_forwarded_host: None,
            x_forwarded_method: None,
            x_forwarded_proto: Some("https".into()),
            x_forwarded_uri: None,
        };
        let result = matches_rule(
            &headers,
            &AuthRule::And(vec![
                AuthRule::HttpProtocol("HTTPS".into()),
                AuthRule::HttpMethod(vec!["GET".into()]),
            ]),
        );
        assert_eq!(result, false);
    }

    #[test]
    fn and_rule_matches_second() {
        let headers = AuthContextHeaders {
            authorization: None,
            x_forwarded_host: None,
            x_forwarded_method: Some("get".into()),
            x_forwarded_proto: Some("https".into()),
            x_forwarded_uri: None,
        };
        let result = matches_rule(
            &headers,
            &AuthRule::And(vec![
                AuthRule::HttpProtocol("HTTP".into()),
                AuthRule::HttpMethod(vec!["GET".into()]),
            ]),
        );
        assert_eq!(result, false);
    }

    #[test]
    fn and_rule_matches_both_matches() {
        let headers = AuthContextHeaders {
            authorization: None,
            x_forwarded_host: None,
            x_forwarded_method: Some("get".into()),
            x_forwarded_proto: Some("https".into()),
            x_forwarded_uri: None,
        };
        let result = matches_rule(
            &headers,
            &AuthRule::And(vec![
                AuthRule::HttpProtocol("HTTP".into()),
                AuthRule::HttpMethod(vec!["GET".into()]),
            ]),
        );
        assert_eq!(result, false);
    }

    #[test]
    fn and_rule_empty_matches() {
        let headers = AuthContextHeaders {
            authorization: None,
            x_forwarded_host: None,
            x_forwarded_method: None,
            x_forwarded_proto: None,
            x_forwarded_uri: None,
        };
        let result = matches_rule(&headers, &AuthRule::And(vec![]));
        assert_eq!(result, true);
    }

    #[test]
    fn pipeline_without_rules_matches() {
        let headers = AuthContextHeaders {
            authorization: None,
            x_forwarded_host: None,
            x_forwarded_method: None,
            x_forwarded_proto: None,
            x_forwarded_uri: None,
        };
        let pipeline = AuthProviders::create_for_testing(vec![AuthPipeline {
            claims: None,
            cookie: Default::default(),
            providers: vec![],
            rules: vec![],
        }]);
        let result = get_pipeline_for_request(&headers, &pipeline);
        assert_eq!(result.is_some(), true);
    }

    #[test]
    fn pipeline_which_matches_one_rule_matches() {
        let headers = AuthContextHeaders {
            authorization: None,
            x_forwarded_host: Some("example.com".into()),
            x_forwarded_method: None,
            x_forwarded_proto: None,
            x_forwarded_uri: None,
        };
        let pipeline = AuthProviders::create_for_testing(vec![AuthPipeline {
            claims: None,
            cookie: Default::default(),
            providers: vec![],
            rules: vec![AuthRule::HttpHost("example.com".into())],
        }]);
        let result = get_pipeline_for_request(&headers, &pipeline);
        assert_eq!(result.is_some(), true);
    }

    #[test]
    fn pipeline_which_matches_all_rules_matches() {
        let headers = AuthContextHeaders {
            authorization: None,
            x_forwarded_host: Some("example.com".into()),
            x_forwarded_method: Some("get".into()),
            x_forwarded_proto: None,
            x_forwarded_uri: None,
        };
        let pipeline = AuthProviders::create_for_testing(vec![AuthPipeline {
            claims: None,
            cookie: Default::default(),
            providers: vec![],
            rules: vec![
                AuthRule::HttpHost("example.com".into()),
                AuthRule::HttpMethod(vec!["get".into()]),
            ],
        }]);
        let result = get_pipeline_for_request(&headers, &pipeline);
        assert_eq!(result.is_some(), true);
    }

    #[test]
    fn pipeline_which_does_not_match_any_rule_does_not_match() {
        let headers = AuthContextHeaders {
            authorization: None,
            x_forwarded_host: None,
            x_forwarded_method: None,
            x_forwarded_proto: None,
            x_forwarded_uri: None,
        };
        let pipeline = AuthProviders::create_for_testing(vec![AuthPipeline {
            claims: None,
            cookie: Default::default(),
            providers: vec![],
            rules: vec![AuthRule::HttpHost("example.com".into())],
        }]);
        let result = get_pipeline_for_request(&headers, &pipeline);
        assert_eq!(result.is_none(), true);
    }
}
