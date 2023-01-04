use crate::{providers::{AuthContextHeaders, AuthProviders}, config::{AuthPipeline, AuthRule}};

pub(crate) fn get_pipeline_for_request<'a>(headers: &AuthContextHeaders, auth_providers: &'a AuthProviders) -> Option<&'a AuthPipeline> {
    auth_providers.pipelines()
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
        AuthRule::HttpHost(host) =>
            headers.x_forwarded_host.as_ref().map_or(false, |h| h.eq_ignore_ascii_case(host)),
        AuthRule::HttpMethod(methods) =>
            headers.x_forwarded_method.as_ref()
                .map_or(false, |m| methods.iter().any(|method| m.eq_ignore_ascii_case(method))),
        AuthRule::HttpPath(path) =>
            headers.x_forwarded_uri.as_ref().map_or(false, |p| p == path),
        AuthRule::HttpPathPrefix(path_prefix) =>
            headers.x_forwarded_uri.as_ref().map_or(false, |p| p.starts_with(path_prefix)),
        AuthRule::HttpProtocol(protocol) =>
            headers.x_forwarded_proto.as_ref().map_or(false, |p| p.eq_ignore_ascii_case(protocol)),
        AuthRule::Or(sub_rules) =>
            sub_rules.iter()
                .map(|sr| matches_rule(headers, sr))
                .reduce(|a, b| a || b)
                .unwrap_or(false),
        AuthRule::And(sub_rules) =>
            sub_rules.iter()
                .map(|sr| matches_rule(headers, sr))
                .reduce(|a, b| a && b)
                .unwrap_or(true),
    }
}