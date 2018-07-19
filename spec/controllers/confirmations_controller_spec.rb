require 'rails_helper'

describe RailsJwtAuth::ConfirmationsController do
  %w(ActiveRecord Mongoid).each do |orm|
    context "when use #{orm}" do
      before :all do
        RailsJwtAuth.model_name = "#{orm}User"
      end

      let(:json) { JSON.parse(response.body) }
      let(:user) { FactoryBot.create("#{orm.underscore}_unconfirmed_user") }

      describe 'POST #create' do
        context 'when sends valid email' do
          it 'returns 201 http status code' do
            post :create, params: {confirmation: {email: user.email}}
            expect(response).to have_http_status(204)
          end

          it 'sends new confirmation email with new token' do
            class Mock
              def deliver
              end
            end

            expect(RailsJwtAuth::Mailer).to receive(:confirmation_instructions)
              .with(user).and_return(Mock.new)

            old_token = user.confirmation_token
            post :create, params: {confirmation: {email: user.email}}
            expect(user.reload.confirmation_token).not_to eq(old_token)
          end
        end

        context 'when send invalid email' do
          before do
            post :create, params: {confirmation: {email: 'invalid'}}
          end

          it 'returns 422 http status code' do
            expect(response).to have_http_status(422)
          end

          it 'returns not found error' do
            expect(json['errors']['email'].first['error']).to eq 'not_found'
          end
        end

        context 'when email is already confirmed' do
          before do
            user.confirm!
            post :create, params: {confirmation: {email: user.email}}
          end

          it 'returns 422 http status code' do
            expect(response).to have_http_status(422)
          end

          it 'returns expiration confirmation error message' do
            expect(json['errors']['email'].first['error']).to eq 'already_confirmed'
          end
        end
      end

      describe 'PUT #update' do
        context 'when sends valid confirmation token' do
          before do
            put :update, params: {confirmation_token: user.confirmation_token}
          end

          it 'returns 204 http status code' do
            expect(response).to have_http_status(204)
          end

          it 'confirms user' do
            expect(user.reload.confirmed?).to be_truthy
          end
        end

        context 'when does not send confirmation token' do
          before do
            FactoryBot.create("#{orm.underscore}_user", password: '12345678')

            put :update
          end

          it 'returns 422 http status code' do
            expect(response).to have_http_status(422)
          end

          it 'does not confirm user' do
            expect(user.reload.confirmed?).to be_falsey
          end

          it 'returns error message' do
            expect(json['errors']['confirmation_token'].first['error']).to eq 'not_found'
          end
        end

        context 'when sends invalid confirmation token' do
          before do
            put :update, params: {confirmation_token: 'invalid'}
          end

          it 'returns 422 http status code' do
            expect(response).to have_http_status(422)
          end

          it 'does not confirm user' do
            expect(user.reload.confirmed?).to be_falsey
          end

          it 'returns error message' do
            expect(json['errors']['confirmation_token'].first['error']).to eq 'not_found'
          end
        end

        context 'when sends expired confirmation token' do
          before do
            user.update(confirmation_sent_at: Time.current - 1.month)
            put :update, params: {confirmation_token: user.confirmation_token}
          end

          it 'returns 422 http status code' do
            expect(response).to have_http_status(422)
          end

          it 'returns expiration confirmation error message' do
            expect(json['errors']['confirmation_token'].first['error']).to eq 'expired'
          end

          it 'does not confirm user' do
            expect(user.reload.confirmed?).to be_falsey
          end
        end
      end
    end
  end
end
