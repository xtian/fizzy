require "test_helper"

class Sessions::OidcControllerTest < ActionDispatch::IntegrationTest
  setup do
    @previous_mappings = Rails.application.config.x.oidc_groups
    Rails.application.config.x.oidc_groups = {
      "acme-eng" => { "account_name" => "Acme Engineering", "default_role" => "member" }
    }

    OmniAuth.config.test_mode = true
  end

  teardown do
    Rails.application.config.x.oidc_groups = @previous_mappings
    OmniAuth.config.test_mode = false
    OmniAuth.config.mock_auth[:oidc] = nil
  end

  test "callback signs in and provisions team access from the group claim" do
    stub_oidc_auth(email: "person@example.com", sub: "sub-person", groups: %w[ acme-eng ])

    untenanted do
      post oidc_callback_url

      assert_response :redirect
      assert cookies[:session_token].present?, "should establish a session"
    end

    identity = Identity.find_by(oidc_subject: "sub-person")
    assert_not_nil identity
    account = Account.find_by(oidc_group: "acme-eng")
    assert identity.users.exists?(account: account), "should be provisioned into the claimed team"
  end

  test "callback with no mapped group grants no account access" do
    stub_oidc_auth(email: "loner@example.com", sub: "sub-loner", groups: %w[ unmapped ])

    untenanted do
      post oidc_callback_url

      assert_response :redirect
      assert cookies[:session_token].present?
    end

    identity = Identity.find_by(oidc_subject: "sub-loner")
    assert_empty identity.users, "unmapped groups grant no team access"
  end

  test "failure redirects to sign in with an alert" do
    untenanted do
      post oidc_failure_url

      assert_redirected_to new_session_path
      assert flash[:alert].present?
    end
  end

  private
    def stub_oidc_auth(email:, sub:, groups: [], verified: true)
      auth = OmniAuth::AuthHash.new(
        provider: "oidc",
        uid: sub,
        info: { email: email },
        extra: { raw_info: { email_verified: verified, groups: groups } }
      )
      OmniAuth.config.mock_auth[:oidc] = auth
      Rails.application.env_config["omniauth.auth"] = auth
    end
end
