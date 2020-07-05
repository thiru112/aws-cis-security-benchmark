class Control:
    """ Collection of controls
    """

    def __init__(self, id, desc, scored):
        self.id = id
        self.desc = desc
        self.scored = scored
        self.result = False
        self._offenders = list()
        self._fail_reason = list()

    @property
    def fail_reason(self):
        return self._fail_reason

    @fail_reason.setter
    def fail_reason(self, reason):
        self._fail_reason.append(reason)

    @property
    def offenders(self):
        return self._offenders

    @offenders.setter
    def offenders(self, offender):
        self._offenders.append(offender)
