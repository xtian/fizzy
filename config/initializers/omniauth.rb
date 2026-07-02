# OpenID Connect sign-in, active only when OIDC_ISSUER is configured. When
# unset, Fizzy falls back to magic-link authentication only.
Rails.application.config.middleware.use OmniAuth::Builder do
  if ENV["OIDC_ISSUER"].present?
    provider :openid_connect,
      name: :oidc,
      issuer: ENV["OIDC_ISSUER"],
      discovery: true,
      scope: ENV.fetch("OIDC_SCOPES", "openid email profile groups").split,
      client_options: {
        identifier: ENV["OIDC_CLIENT_ID"],
        secret: ENV["OIDC_CLIENT_SECRET"],
        redirect_uri: ENV["OIDC_REDIRECT_URI"].presence ||
          "#{ENV.fetch("BASE_URL", "http://localhost:3000")}/auth/oidc/callback"
      }
  end
end

# The omniauth-rails_csrf_protection gem requires the request phase to be a POST.
OmniAuth.config.allowed_request_methods = %i[ post ]
OmniAuth.config.silence_get_warning = true

OmniAuth.config.on_failure = ->(env) { Sessions::OidcController.action(:failure).call(env) }
