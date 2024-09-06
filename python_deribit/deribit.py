from python_deribit import DeribitAPI


class Deribit(DeribitAPI):
    def __init__(self, api_key, api_secret, base_url=None):
        super().__init__(api_key, api_secret, base_url)

    def get_account_summaries(self, **kwargs):
        url_path = '/private/get_account_summaries'
        return self.send_request(**self.sign(url_path, 'GET', kwargs))

    def get_subaccounts(self, **kwargs):
        url_path = '/private/get_subaccounts'
        return self.send_request(**self.sign(url_path, 'GET', kwargs))
