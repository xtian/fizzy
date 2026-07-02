class Sessions::OidcController < ApplicationController
  disallow_account_scope
  allow_unauthenticated_access
  skip_forgery_protection only: :create
  rate_limit to: ENV.fetch("OIDC_RATE_LIMIT", 10).to_i, within: 3.minutes, only: :create, with: :rate_limit_exceeded

  layout "public"

  def create
    if identity = Identity.find_or_create_from_oidc(auth_hash)
      Rails.logger.info "[OIDC] Sign-in for #{auth_hash.info&.email}"
      identity.reconcile_oidc_memberships(oidc_groups)
      start_new_session_for identity
      redirect_to after_authentication_url
    else
      authentication_failed
    end
  end

  def failure
    authentication_failed message: "Something went wrong using your provider. Please try again."
  end

  private
    def auth_hash
      request.env["omniauth.auth"]
    end

    def oidc_groups
      auth_hash&.extra&.raw_info&.groups || []
    end

    def authentication_failed(message: "We couldn't sign you in. Please try again.")
      Rails.logger.warn "[OIDC] Authentication failed: #{message}"
      redirect_to new_session_path, alert: message
    end

    def rate_limit_exceeded
      redirect_to new_session_path, alert: "Try again later."
    end
end
