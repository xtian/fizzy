require "test_helper"

class Identity::OidcCompatibleTest < ActiveSupport::TestCase
  setup do
    @previous_mappings = Rails.application.config.x.oidc_groups
    Rails.application.config.x.oidc_groups = {
      "acme-eng" => { "account_name" => "Acme Engineering", "default_role" => "member" },
      "acme-sales" => { "account_name" => "Acme Sales", "default_role" => "member" }
    }
  end

  teardown do
    Rails.application.config.x.oidc_groups = @previous_mappings
  end

  # Find or create ----------------------------------------------------------

  test "creates a new identity from OIDC" do
    assert_difference "Identity.count", 1 do
      identity = Identity.find_or_create_from_oidc(auth_hash(email: "new@example.com", sub: "sub-new"))
      assert_equal "new@example.com", identity.email_address
      assert_equal "sub-new", identity.oidc_subject
      assert_equal "oidc", identity.oidc_provider
    end
  end

  test "links an existing identity by email on first OIDC login" do
    existing = identities(:kevin)

    assert_no_difference "Identity.count" do
      identity = Identity.find_or_create_from_oidc(auth_hash(email: existing.email_address, sub: "sub-kevin"))
      assert_equal existing, identity
      assert_equal "sub-kevin", identity.reload.oidc_subject
    end
  end

  test "finds an already-linked identity by subject" do
    existing = identities(:kevin)
    existing.update!(oidc_provider: "oidc", oidc_subject: "sub-kevin")

    identity = Identity.find_or_create_from_oidc(auth_hash(email: existing.email_address, sub: "sub-kevin"))
    assert_equal existing, identity
  end

  test "returns nil when subject or email is missing" do
    assert_nil Identity.find_or_create_from_oidc(auth_hash(email: "x@example.com", sub: nil))
    assert_nil Identity.find_or_create_from_oidc(auth_hash(email: nil, sub: "sub-x"))
  end

  # Membership reconciliation ----------------------------------------------

  test "grants access to accounts for claimed groups" do
    identity = Identity.find_or_create_from_oidc(auth_hash(email: "person@example.com", sub: "sub-person"))

    identity.reconcile_oidc_memberships(%w[ acme-eng ])

    account = Account.find_by(oidc_group: "acme-eng")
    assert identity.users.exists?(account: account), "should be a member of the claimed account"
    assert_equal "member", identity.users.find_by(account: account).role
  end

  test "ignores unmapped groups" do
    identity = Identity.find_or_create_from_oidc(auth_hash(email: "person@example.com", sub: "sub-person"))

    assert_no_difference "Account.count" do
      identity.reconcile_oidc_memberships(%w[ unmapped-team ])
    end
    assert_empty identity.reload.users
  end

  test "revokes access to managed accounts no longer claimed" do
    identity = Identity.find_or_create_from_oidc(auth_hash(email: "person@example.com", sub: "sub-person"))

    identity.reconcile_oidc_memberships(%w[ acme-eng acme-sales ])
    eng = Account.find_by(oidc_group: "acme-eng")
    sales = Account.find_by(oidc_group: "acme-sales")
    assert identity.users.exists?(account: eng)
    assert identity.users.exists?(account: sales)

    identity.reconcile_oidc_memberships(%w[ acme-eng ])
    assert identity.reload.users.exists?(account: eng), "kept claimed membership"
    assert_not identity.users.exists?(account: sales), "revoked unclaimed membership"
  end

  test "never touches memberships in unmanaged accounts" do
    identity = identities(:david)
    unmanaged = accounts(:initech)
    Current.without_account { identity.join(unmanaged) }

    identity.reconcile_oidc_memberships([])

    assert identity.reload.users.exists?(account: unmanaged), "magic-link account membership must be preserved"
  end

  private
    def auth_hash(email:, sub:, groups: [], verified: true)
      OmniAuth::AuthHash.new(
        provider: "oidc",
        uid: sub,
        info: { email: email },
        extra: { raw_info: { email_verified: verified, groups: groups } }
      )
    end
end
