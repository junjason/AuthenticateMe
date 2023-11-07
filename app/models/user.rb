class User < ApplicationRecord
  has_secure_password

  validates :username, uniqueness: true, length: { in: 3..30 }, format: { without: URI::MailTo::EMAIL_REGEXP, message:  "can't be an email" }
  validates :email, uniqueness: true, length: { in: 3..255 }, format: { with: URI::MailTo::EMAIL_REGEXP }
  validates :session_token, presence: true, uniqueness: true
  validates :password, length: { in: 6..255 }, allow_nil: true

  before_validation :ensure_session_token

  def self.find_by_credentials(credential, password)
    # determine the field you need to query: 
    #   * `email` if `credential` matches `URI::MailTo::EMAIL_REGEXP`
    #   * `username` if not
    # find the user whose email/username is equal to `credential`
    isEmail = false;
    if (credential.match(URI::MailTo::EMAIL_REGEXP)) isEmail = true;
    
    user = nil;
    if (isEmail) user = User.find_by(email: credential)
    else user = User.find_by(username: credential)

    # if no such user exists, return a falsey value

    # if a matching user exists, use `authenticate` to check the provided password
    # return the user if the password is correct, otherwise return a falsey value

    if user&.authenticate(password)
      return user
    else 
      nil
    end
  end

  def reset_session_token!
    self.session_token = generate_unique_session_token
    self.save!
    self.session_token
  end

  private
  def generate_unique_session_token
    loop do 
      token = SecureRandom.urlsafe_base64
      return token if !User.exists?(session_token: token)
    end
  end

  def ensure_session_token
    self.session_token ||= generate_unique_session_token
  end
end
