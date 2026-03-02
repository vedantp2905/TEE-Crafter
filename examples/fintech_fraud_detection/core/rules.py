from schemas.transaction import Transaction

class FraudRulesEngine:
    def __init__(self):
        self.blacklisted_devices = {"DEV-999", "DEV-666"}
        self.high_risk_countries = {"XX", "YY"} # Anonymized codes

    def check_velocity(self, txn: Transaction) -> bool:
        # Mock velocity check (in real app would check DB state)
        return txn.amount > 10000

    def check_blacklist(self, txn: Transaction) -> bool:
        return txn.device_id in self.blacklisted_devices

    def check_geolocation(self, txn: Transaction) -> bool:
        return txn.location.country_code in self.high_risk_countries
