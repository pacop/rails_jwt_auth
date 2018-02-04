module RailsJwtAuth
  module AuthenticableHelper
    RailsJwtAuth::NotAuthorized = Class.new(StandardError)

    def current_user
      @current_user
    end

    def signed_in?
      !current_user.nil?
    end

    def authenticate!
      unauthorize! unless request.env['HTTP_AUTHORIZATION']
      token = request.env['HTTP_AUTHORIZATION'].split.last

      begin
        payload = JwtManager.decode(token).first.with_indifferent_access
        unauthorize! unless JwtManager.valid_payload?(payload)

        user_payload = payload[RailsJwtAuth.model.to_s.underscore]
        @current_user = RailsJwtAuth.model.from_token_payload(user_payload)
      rescue
        unauthorize!
      end
    end

    def unauthorize!
      raise NotAuthorized
    end

    def self.included(base)
      return unless Rails.env.test? && base.name == 'ApplicationController'

      base.send(:rescue_from, RailsJwtAuth::Spec::NotAuthorized) do
        render json: {}, status: 401
      end
    end
  end
end
