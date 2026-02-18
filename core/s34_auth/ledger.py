class KeyLedger:

    def __init__(self):
        self._records = []

    def record_usage(self, record: KeyUsageRecord):

        self._records.append(record)

    def get_records_for_subject(self, subject_id: str):

        return [
            r for r in self._records
            if r.subject_id == subject_id
        ]

    def get_records_for_key(self, key_id: str):

        return [
            r for r in self._records
            if r.key_id == key_id
        ]