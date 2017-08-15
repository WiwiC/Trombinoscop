# This file should contain all the record creation needed to seed the database with its default values.
# The data can then be loaded with the rails db:seed command (or created alongside the database with db:setup).
#
# Examples:
#
#   movies = Movie.create([{ name: 'Star Wars' }, { name: 'Lord of the Rings' }])
#   Character.create(name: 'Luke', movie: movies.first)

# uploader = ImageUploader.new
# uploader.store!('image.png')

def seed_image(file_name)
  # File.open(File.join(Rails.root, "/app/assets/images/#{file_name}.jpg"))
  File.open(File.join(Rails.root, "/app/assets/images/#{file_name}.jpg"))
end

image = seed_image('image')

c = User.create!(username:  "Claire",
             email: "claire@example.com",
             password:              "password",
             password_confirmation: "password",
             bio: "Claire' bio",
             slack_handle: "@claire",
             image: image,)
  c.skip_confirmation!
  c.save

20.times do |n|
  name  = Faker::Name.name
  email = "example-#{n+1}@example.com"
  password = "password"
  bio_text = Faker::Lorem.sentence(5)
  slack = "@slack#{n+1}"
  u = User.create!(username:  name,
              email: email,
              password:              password,
              password_confirmation: password,
              bio: bio_text,
              slack_handle: slack,
              image: image)
  u.skip_confirmation!
  u.save

end