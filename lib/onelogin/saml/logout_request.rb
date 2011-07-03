require "base64"
require "uuid"
require "zlib"
require "cgi"

module Onelogin::Saml
  class LogoutRequest
    def create(settings, name_id, session_index, params = {})
      uuid = "_" + UUID.new.generate
      time = Time.now.utc.strftime("%Y-%m-%dT%H:%M:%SZ")

      request = 
        "<saml2p:LogoutRequest xmlns:saml2p=\"urn:oasis:names:tc:SAML:2.0:protocol\" ID=\"#{uuid}\" IssueInstant=\"#{time}\" Version=\"2.0\">" +
        "<saml2:Issuer xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\">#{settings.issuer}</saml2:Issuer>" + 
        "<saml2:NameID xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" Format=\"#{settings.name_identifier_format}\">#{name_id}</saml2:NameID>" +
        "<saml2p:SessionIndex>#{session_index}</saml2p:SessionIndex>" + 
        "</saml2p:LogoutRequest>"

      deflated_request  = Zlib::Deflate.deflate(request, 9)[2..-5]
      base64_request    = Base64.encode64(deflated_request)
      encoded_request   = CGI.escape(base64_request)
      request_params    = "?SAMLRequest=" + encoded_request

      params.each_pair do |key, value|
        request_params << "&#{key}=#{CGI.escape(value.to_s)}"
      end

      settings.idp_sso_target_url + request_params
    end

  end
end
