module DNS::EXTENSIONS;


event dns_OPT(c: connection, msg: dns_msg, ans: dns_edns_additional, code: count, val: string) {
  local is_query: bool = T ? ans$is_query == 1 : F;

  if (code == 0) {
    event DNS::EXTENSIONS::reserved(c, is_query, DNS::EXTENSIONS::parse_reserved(val));
  } else if (code == 1) {
    event DNS::EXTENSIONS::llq(c, is_query, DNS::EXTENSIONS::parse_llq(val));
  } else if (code == 2) {
    event DNS::EXTENSIONS::update_lease(c, is_query, DNS::EXTENSIONS::parse_update_lease(val));
  } else if (code == 3) {
    event DNS::EXTENSIONS::nsid(c, is_query, DNS::EXTENSIONS::parse_nsid(val));
  } else if (code == 4) {
    event DNS::EXTENSIONS::reserved(c, is_query, DNS::EXTENSIONS::parse_reserved(val));
  } else if (code == 5) {
    event DNS::EXTENSIONS::dau(c, is_query, DNS::EXTENSIONS::parse_dau(val));
  } else if (code == 6) {
    event DNS::EXTENSIONS::dhu(c, is_query, DNS::EXTENSIONS::parse_dhu(val));
  } else if (code == 7) {
    event DNS::EXTENSIONS::n3u(c, is_query, DNS::EXTENSIONS::parse_n3u(val));
  } else if (code == 8) {
    event DNS::EXTENSIONS::edns_client_subnet(c, is_query, DNS::EXTENSIONS::parse_edns_client_subnet(val));
  } else if (code == 9) {
    event DNS::EXTENSIONS::edns_expire(c, is_query, DNS::EXTENSIONS::parse_edns_expire(val));
  } else if (code == 10) {
    event DNS::EXTENSIONS::cookie(c, is_query, DNS::EXTENSIONS::parse_cookie(val));
  } else if (code == 11) {
    event DNS::EXTENSIONS::edns_tcp_keepalive(c, is_query, DNS::EXTENSIONS::parse_edns_tcp_keepalive(val));
  } else if (code == 12) {
    event DNS::EXTENSIONS::padding(c, is_query, DNS::EXTENSIONS::parse_padding(val));
  } else if (code == 13) {
    event DNS::EXTENSIONS::chain(c, is_query, DNS::EXTENSIONS::parse_chain(val));
  } else if (code == 14) {
    event DNS::EXTENSIONS::edns_key_tag(c, is_query, DNS::EXTENSIONS::parse_edns_key_tag(val));
  } else if (code == 15) {
    event DNS::EXTENSIONS::extended_dns_error(c, is_query, DNS::EXTENSIONS::parse_extended_dns_error(val));
  } else if (code == 16) {
    event DNS::EXTENSIONS::edns_client_tag(c, is_query, DNS::EXTENSIONS::parse_edns_client_tag(val));
  } else if (code == 17) {
    event DNS::EXTENSIONS::edns_server_tag(c, is_query, DNS::EXTENSIONS::parse_edns_server_tag(val));
  } else if (code == 18) {
    event DNS::EXTENSIONS::report_channel(c, is_query, DNS::EXTENSIONS::parse_report_channel(val));
  } else if (code == 19) {
    event DNS::EXTENSIONS::zoneversion(c, is_query, DNS::EXTENSIONS::parse_zoneversion(val));
  } else if (code >= 20 && code <= 20291) {
    event DNS::EXTENSIONS::unassigned(c, is_query, DNS::EXTENSIONS::parse_unassigned(val));
  } else if (code == 20292) {
    event DNS::EXTENSIONS::umbrella_ident(c, is_query, DNS::EXTENSIONS::parse_umbrella_ident(val));
  } else if (code >= 20293 && code <= 26945) {
    event DNS::EXTENSIONS::unassigned(c, is_query, DNS::EXTENSIONS::parse_unassigned(val));
  } else if (code == 26946) {
    event DNS::EXTENSIONS::device_id(c, is_query, DNS::EXTENSIONS::parse_device_id(val));
  } else if (code >= 26947 && code <= 65000) {
    event DNS::EXTENSIONS::unassigned(c, is_query, DNS::EXTENSIONS::parse_unassigned(val));
  } else if (code >= 65001 && code <= 65534) {
    event DNS::EXTENSIONS::reserved_local_experimental(c, is_query, DNS::EXTENSIONS::parse_reserved_local_experimental(val));
  } else if (code == 65535) {
    event DNS::EXTENSIONS::reserved_future_expansion(c, is_query, DNS::EXTENSIONS::parse_reserved_future_expansion(val));
  } else {
    # TODO - raise a weird
    ;
  }
}
