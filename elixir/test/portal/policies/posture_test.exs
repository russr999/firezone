defmodule Portal.Policies.PostureTest do
  use ExUnit.Case, async: true

  alias Portal.Policies.Posture

  describe "normalize/1" do
    test "keeps only recognized keys and drops the rest" do
      result =
        Posture.normalize(%{
          "os_type" => "Windows",
          "os_version" => " 10.0.22631 ",
          "disk_encryption" => true,
          "firewall_enabled" => "false",
          "antivirus_enabled" => nil,
          "client_version" => "1.5.7",
          "evil" => "drop me"
        })

      assert result == %{
               "os_type" => "windows",
               "os_version" => "10.0.22631",
               "client_version" => "1.5.7",
               "disk_encryption" => true,
               "firewall_enabled" => false,
               "antivirus_enabled" => nil
             }

      refute Map.has_key?(result, "evil")
    end

    test "decodes a JSON object string (the wire form)" do
      json = ~s({"os_type":"linux","disk_encryption":true})
      result = Posture.normalize(json)
      assert result["os_type"] == "linux"
      assert result["disk_encryption"] == true
      assert result["os_version"] == nil
    end

    test "rejects unknown os types" do
      assert Posture.normalize(%{"os_type" => "haiku"})["os_type"] == nil
    end

    test "returns nil for non-map / non-object input" do
      assert Posture.normalize(nil) == nil
      assert Posture.normalize("not json") == nil
      assert Posture.normalize("[1,2,3]") == nil
      assert Posture.normalize(123) == nil
    end
  end

  describe "compare_versions/2 and version_at_least?/2" do
    test "orders dotted numeric versions" do
      assert Posture.compare_versions("10.0.22631", "10.0.22000") == :gt
      assert Posture.compare_versions("1.5.7", "1.5.7") == :eq
      assert Posture.compare_versions("1.4.0", "1.5.0") == :lt
    end

    test "treats missing trailing segments as zero" do
      assert Posture.compare_versions("14", "14.0.0") == :eq
      assert Posture.compare_versions("14.1", "14") == :gt
    end

    test "errors on unparseable input" do
      assert Posture.compare_versions("abc", "1.0") == :error
      assert Posture.compare_versions("1.0", nil) == :error
    end

    test "version_at_least? fails closed on missing/unparseable" do
      assert Posture.version_at_least?("1.5.7", "1.5.0")
      assert Posture.version_at_least?("1.5.0", "1.5.0")
      refute Posture.version_at_least?("1.4.0", "1.5.0")
      refute Posture.version_at_least?(nil, "1.5.0")
      refute Posture.version_at_least?("garbage", "1.5.0")
    end
  end
end
