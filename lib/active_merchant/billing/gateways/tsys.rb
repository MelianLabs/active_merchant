module ActiveMerchant #:nodoc:
  module Billing #:nodoc:
    class TsysGateway < Gateway
      self.test_url = 'https://stagegw.transnox.com/servlets/TransNox_API_Server'
      self.live_url = ''

      self.default_currency             = 'USD'
      self.money_format                 = :cents
      self.supported_countries          = %w(AT AU BE BR CA CH DE DK ES FI FR GB HK IE IT JP LU MX NL NO NZ PT SE SG US)
      self.supported_cardtypes          = [:visa, :master, :american_express, :discover, :jcb, :diners_club]
      self.currencies_without_fractions = %w(BIF CLP DJF GNF JPY KMF KRW MGA PYG RWF VND VUV XAF XOF XPF)
      self.homepage_url                 = 'http://www.tsys.com/'
      self.display_name                 = 'TSYS'

      AUTH_FINAL   = 'FINAL'.freeze
      AUTH_PREAUTH = 'PREAUTH'.freeze
      CARD_CODES   = {
        'visa' =>             'V',
        'master' =>           'M',
        'american_express' => 'X',
        'discover' =>         'R',
        'jcb' =>              'J',
        'diners_club' =>      'I'
      }.freeze

      # This is not all the error codes provided by TSYS. More time can be spent to map more completely. For now
      # all unmapped values will go to :processing_error
      STANDARD_ERROR_CODE_MAPPING = {
        'D0006' => STANDARD_ERROR_CODE[:unsupported_feature],
        'E0010' => STANDARD_ERROR_CODE[:config_error],
        'E0011' => STANDARD_ERROR_CODE[:config_error],
        'E0012' => STANDARD_ERROR_CODE[:unsupported_feature],
        'E0013' => STANDARD_ERROR_CODE[:unsupported_feature],
        'E0020' => STANDARD_ERROR_CODE[:config_error],
        'E0021' => STANDARD_ERROR_CODE[:config_error],
        'E0022' => STANDARD_ERROR_CODE[:config_error],
        'D0023' => STANDARD_ERROR_CODE[:config_error],
        'E0030' => STANDARD_ERROR_CODE[:config_error],
        'D0050' => STANDARD_ERROR_CODE[:config_error],
        'D0060' => STANDARD_ERROR_CODE[:config_error],
        'D0070' => STANDARD_ERROR_CODE[:config_error],
        'D0097' => STANDARD_ERROR_CODE[:unsupported_feature],
        'D1003' => STANDARD_ERROR_CODE[:invalid_number],
        'D1004' => STANDARD_ERROR_CODE[:config_error],
        'D1005' => STANDARD_ERROR_CODE[:config_error],
        'D1006' => STANDARD_ERROR_CODE[:config_error],
        'D1007' => STANDARD_ERROR_CODE[:config_error],
        'D1020' => STANDARD_ERROR_CODE[:config_error],
        'D1201' => STANDARD_ERROR_CODE[:config_error],
        'D1203' => STANDARD_ERROR_CODE[:config_error],
        'D1206' => STANDARD_ERROR_CODE[:config_error],
        'D1215' => STANDARD_ERROR_CODE[:invalid_number],
        'D2001' => STANDARD_ERROR_CODE[:call_issuer],
        'D2002' => STANDARD_ERROR_CODE[:pick_up_card],
        'D2008' => STANDARD_ERROR_CODE[:incorrect_pin],
        'D2009' => STANDARD_ERROR_CODE[:incorrect_pin],
        'D2011' => STANDARD_ERROR_CODE[:expired_card],
        'D2013' => STANDARD_ERROR_CODE[:config_error],
        'D2014' => STANDARD_ERROR_CODE[:config_error],
        'D2018' => STANDARD_ERROR_CODE[:incorrect_address],
        'D2019' => STANDARD_ERROR_CODE[:config_error],
        'D2020' => STANDARD_ERROR_CODE[:invalid_cvc],
        'D2021' => STANDARD_ERROR_CODE[:call_issuer],
        'D2024' => STANDARD_ERROR_CODE[:invalid_number],
        'D2025' => STANDARD_ERROR_CODE[:card_declined],
        'D2026' => STANDARD_ERROR_CODE[:card_declined],
        'D2027' => STANDARD_ERROR_CODE[:card_declined],
        'D2028' => STANDARD_ERROR_CODE[:invalid_expiry_date],
        'D2029' => STANDARD_ERROR_CODE[:unsupported_feature],
        'D2030' => STANDARD_ERROR_CODE[:config_error],
        'D2031' => STANDARD_ERROR_CODE[:card_declined],
        'D2032' => STANDARD_ERROR_CODE[:card_declined],
        'D2999' => STANDARD_ERROR_CODE[:card_declined],
        'E6004' => STANDARD_ERROR_CODE[:incorrect_address],
        'E6999' => STANDARD_ERROR_CODE[:card_declined],
        'D9000' => STANDARD_ERROR_CODE[:card_declined],
        'D9001' => STANDARD_ERROR_CODE[:card_declined],
        'D9002' => STANDARD_ERROR_CODE[:card_declined],
        'D9003' => STANDARD_ERROR_CODE[:card_declined],
        'F9901' => STANDARD_ERROR_CODE[:config_error]
        # 'E0713' - TRANSACTION KEY EXPIRED
      }
      STATUS_PASS                 = 'PASS'.freeze

      # TransIT processes the transaction as card not present if the field value is PHONE, MAIL, or INTERNET.
      # For any other, TransIT processes the transaction as card present.
      CARD_DATA_SOURCES = %w[BAR_CODE EMV EMV_CONTACTLESS FALLBACK_SWIPE INTERNET MAIL MANUAL NFC PHONE SWIPE].freeze

      def initialize(options = {})
        requires!(options, :developer_id, :device_id)

        @device_id       = options[:device_id]
        @transaction_key = options[:transaction_key] || nil
        @developer_id    = options[:developer_id]

        super
      end

      def authorize(money, payment_method, options = {})
        requires!(options, [:card_data_source, *CARD_DATA_SOURCES])
        commit(:post, build_auth_or_purchase_request(money, payment_method, options), options)
      end

      def capture(money, authorization, options = {})
        commit(:post, build_capture_request(money, authorization, options), options)
      end

      def generate_key(merchant_id, user_id, password, options = {})
        commit(:post, build_generate_key_request(merchant_id, user_id, password, options))
      end

      def purchase(money, payment_method, options = {})
        requires!(options, [:card_data_source, *CARD_DATA_SOURCES])
        commit(:post, build_auth_or_purchase_request(money, payment_method, options, false), options)
      end

      def refund(money, authorization, options = {})
        commit(:post, build_void_request(money, authorization, options), options)
      end

      def verify(payment, options={})
        commit(:post, build_verify_request(payment, options), options)
      end

      def void(_authorization, _options = {})
        commit(:post, build_void_request(nil, authorization, options), options)
      end

      def supports_scrubbing
        true
      end

      def scrub(transcript)
        transcript.
          gsub(%r((Authorization: Basic )\w+), '\1[FILTERED]').
          gsub(%r((<cardNumber>)\d+(</cardNumber>)), '\1[FILTERED]\2').
          gsub(%r((<cvc>)[^<]+(</cvc>)), '\1[FILTERED]\2')
      end

      private

      def add_address(post, options)
        if address = options[:billing_address] || options[:address]
          post[:addressLine1] = address[:address1] if address[:address1]
          post[:zip]          = address[:zip] if address[:zip]
        end
      end

      def add_amount(post, money, options, include_currency: false)
        currency                 = options[:currency] || currency(money)
        post[:transactionAmount] = localized_amount(money, currency)
        post[:currencyCode]      = currency if include_currency
      end

      def add_creditcard(post, creditcard, options)
        if emv_payment?(creditcard)
          # add_emv_creditcard(post, creditcard.icc_data)
          # post[:card][:read_method] = "contactless" if creditcard.contactless_emv
          # post[:card][:read_method] = "contactless_magstripe_mode" if creditcard.contactless_magstripe
          # if creditcard.encrypted_pin_cryptogram.present? && creditcard.encrypted_pin_ksn.present?
          #   post[:card][:encrypted_pin] = creditcard.encrypted_pin_cryptogram
          #   post[:card][:encrypted_pin_key_id] = creditcard.encrypted_pin_ksn
          # end
        elsif creditcard.respond_to?(:number)
          if creditcard.respond_to?(:track_data) && creditcard.track_data.present?
            # card[:swipe_data] = creditcard.track_data
            # card[:fallback_reason] = creditcard.fallback_reason if creditcard.fallback_reason
            # card[:read_method] = "contactless" if creditcard.contactless_emv
            # card[:read_method] = "contactless_magstripe_mode" if creditcard.contactless_magstripe
          else
            post[:cardNumber]     = creditcard.number
            post[:expirationDate] = sprintf('%02d', creditcard.month) + creditcard.year.to_s
            post[:cvv2]           = creditcard.verification_value if creditcard.verification_value?
            post[:cardHolderName] = creditcard.name if creditcard.name?
          end

          # if creditcard.is_a?(NetworkTokenizationCreditCard)
          #   card[:cryptogram] = creditcard.payment_cryptogram
          #   card[:eci] = creditcard.eci.rjust(2, '0') if creditcard.eci =~ /^[0-9]+$/
          #   card[:tokenization_method] = creditcard.source.to_s
          # end
          # post[:card] = card

          add_address(post, options)
        elsif creditcard.kind_of?(String)
          post[:cardNumber] = creditcard
        end
      end

      def add_key_information(post, options)
        post[:deviceID]       = @device_id
        post[:transactionKey] = @transaction_key
      end

      # The commented fields seems to be not mandatory according to the sandbox server, for now.
      def add_terminal_information(post, options)
        requires!(options,
                  :terminal_capability,
                  :terminal_operating_environment,
                  :cardholder_authentication_method,
        # :terminal_authentication_capability,
        # :terminal_output_capability,
        # :max_pin_length
        )

        post[:terminalCapability]             = options[:terminal_capability]
        post[:terminalOperatingEnvironment]   = options[:terminal_operating_environment]
        post[:cardholderAuthenticationMethod] = options[:cardholder_authentication_method]
        # post[:terminalAuthenticationCapability] = options[:terminal_authentication_capability]
        # post[:terminalOutputCapability]         = options[:terminal_output_capability]
        # post[:maxPinLength]                     = options[:max_pin_length]
      end

      def build_generate_key_request(merchant_id, user_id, password, options)
        message = { GenerateKey: {} }
        post    = message[:GenerateKey]

        post[:mid]            = merchant_id
        post[:userID]         = user_id
        post[:password]       = password
        post[:developerID]    = @developer_id
        post[:transactionKey] = @transaction_key if @transaction_key.present?

        message
      end

      # IMPORTANT: although JSON encoded, the order of fields are important, so don't move things around!
      def build_auth_or_purchase_request(money, payment_method, options, auth = true)
        requires!(options, :card_data_source)

        message = auth ? { Auth: {} } : { Sale: {} }
        post    = message[auth ? :Auth : :Sale]

        add_key_information(post, options)

        post[:cardDataSource] = options[:card_data_source]

        add_amount(post, money, options, include_currency: true)
        add_creditcard(post, payment_method, options)

        post[:orderNumber]    = options[:order_id]
        post[:softDescriptor] = options[:statement_descriptor] if options[:statement_descriptor]

        add_terminal_information(post, options)

        post[:developerID]            = @developer_id
        post[:laneID]                 = options[:lane_id] if options[:lane_id]
        post[:authorizationIndicator] = auth ? AUTH_PREAUTH : AUTH_FINAL

        message
      end

      def build_capture_request(money, authorization, options)
        message = { Capture: {} }
        post    = message[:Capture]

        add_key_information(post, options)

        add_amount(post, money, options, include_currency: false)

        post[:transactionID] = authorization
        post[:developerID]   = @developer_id

        message
      end

      def build_verify_request(payment_method, options)
        requires!(options, :card_data_source)

        message = { CardAuthentication: {} }
        post    = message[:CardAuthentication]

        add_key_information(post, options)

        post[:cardDataSource] = options[:card_data_source]

        add_creditcard(post, payment_method, options)

        post[:developerID]            = @developer_id
        post[:laneID]                 = options[:lane_id] if options[:lane_id]

        add_terminal_information(post, options)

        message
      end

      def build_void_request(money, authorization, options)
        message = { Void: {} }
        post    = message[:Void]

        add_key_information(post, options)

        add_amount(post, money, options, include_currency: false)

        post[:transactionID] = authorization
        post[:developerID]   = @developer_id

        message
      end

      def emv_payment?(payment)
        payment.respond_to?(:emv?) && payment.emv?
      end

      def check_and_strip_tag(response, parameters)
        req_key = parameters.first[0]
        rsp_key = response.first[0]
        raise StandardError, "Protocol mismatch. #{req_key.to_s + 'Response'} expected, got #{rsp_key}" if req_key.to_s + 'Response' != rsp_key
        response[rsp_key]
      end

      def api_request(method, parameters = nil, options = {})
        raw_response = response = nil
        begin
          raw_response = ssl_request(method, url, post_data(parameters), headers(options))
          response     = parse(raw_response)
          response     = check_and_strip_tag(response, parameters)
        rescue ResponseError => e
          raw_response = e.response.body
          response     = response_error(raw_response)
        rescue JSON::ParserError
          response = json_error(raw_response)
        end
        response
      end

      def commit(method, parameters = nil, options = {})
        response = api_request(method, parameters, options)

        success = !response.key?('error') && response['status'] == STATUS_PASS

        Response.new(success,
                     "#{response['responseCode']} #{response['responseMessage']}",
                     response,
                     test:              test?,
                     authorization:     success ? response['transactionID'] : '',
                     avs_result:        { code: response['addressVerificationCode'] ? response['addressVerificationCode'] : 'U' },
                     cvv_result:        response['cvvVerificationCode'] ? response['cvvVerificationCode'] : 'M',
                     emv_authorization: 'TBD', #TODO: later
                     error_code: success ? nil : error_code_from(response)
        )
      end

      def error_code_from(response)
        code = response['responseCode']
        STANDARD_ERROR_CODE_MAPPING[code] || STANDARD_ERROR_CODE[:processing_error]
      end

      def headers(_options = {})
        headers = { 'user-agent' => 'infonox' }

        headers
      end

      def json_error(raw_response)
        msg = 'Invalid response received from the TSYS API.  Please contact support@tsys.com if you continue to receive this message.'
        msg += "  (The raw response returned by the API was #{raw_response.inspect})"
        {
          'error' => {
            'message' => msg
          }
        }
      end

      def parse(body)
        JSON.parse(body)
      end

      def post_data(parameters = {})
        JSON.generate(parameters)
      end

      def response_error(raw_response)
        begin
          parse(raw_response)
        rescue JSON::ParserError
          json_error(raw_response)
        end
      end

      def url
        test? ? self.test_url : self.live_url
      end
    end
  end
end
