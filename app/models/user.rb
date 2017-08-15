class User < ApplicationRecord
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable and :omniauthable
  mount_uploader :image, ImageUploader

  validates :slack_handle, format: { without: /\s/ } #ON ACCEPTE PAS LES ESPACES DANS LA ZONE DE TEXT DU slack

  validates :username, presence: true, uniqueness: {case_sensitive: false}, format: {with: /\A[a-zA-Z0-9 _\.]*\z/}
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :trackable, :validatable, :confirmable
end
