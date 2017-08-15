class HomeController < ApplicationController
  def trombi
    @users = User.all
  end
end
