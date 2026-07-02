require "test_helper"

class Oidc::GroupMapTest < ActiveSupport::TestCase
  setup do
    @previous_mappings = Rails.application.config.x.oidc_groups
    Rails.application.config.x.oidc_groups = {
      "acme-eng" => { "account_name" => "Acme Engineering", "default_role" => "member" },
      "acme-admins" => { "account_name" => "Acme Admins", "default_role" => "admin" }
    }
  end

  teardown do
    Rails.application.config.x.oidc_groups = @previous_mappings
  end

  test "admit keeps only mapped groups" do
    assert_equal [ "acme-eng" ], Oidc::GroupMap.admit(%w[ acme-eng unmapped ])
  end

  test "admit normalizes path-style group names" do
    assert_equal [ "acme-eng" ], Oidc::GroupMap.admit([ "/some/path/acme-eng" ])
  end

  test "admit dedupes" do
    assert_equal [ "acme-eng" ], Oidc::GroupMap.admit(%w[ acme-eng acme-eng ])
  end

  test "account_for creates the account once and stamps the group" do
    account = nil
    assert_difference "Account.count", 1 do
      account = Oidc::GroupMap.account_for("acme-eng")
    end

    assert_equal "acme-eng", account.oidc_group
    assert_equal "Acme Engineering", account.name
    assert account.users.exists?(role: :system), "auto-created account should have a system user"

    assert_no_difference "Account.count" do
      assert_equal account, Oidc::GroupMap.account_for("acme-eng")
    end
  end

  test "account_for returns nil for an unmapped group" do
    assert_nil Oidc::GroupMap.account_for("unmapped")
  end

  test "default_role falls back to member" do
    assert_equal :admin, Oidc::GroupMap.default_role("acme-admins")
    assert_equal :member, Oidc::GroupMap.default_role("acme-eng")
  end

  test "managed_accounts lists only OIDC-stamped accounts" do
    account = Oidc::GroupMap.account_for("acme-eng")
    assert_includes Oidc::GroupMap.managed_accounts, account
    assert_not_includes Oidc::GroupMap.managed_accounts, accounts(:initech)
  end
end
