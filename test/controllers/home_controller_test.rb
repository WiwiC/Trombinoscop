require 'test_helper'

class HomeControllerTest < ActionDispatch::IntegrationTest
  test "should get trombi" do
    get home_trombi_url
    assert_response :success
  end

end
