    def populate(self, *args, **kwargs):
        logger.trace(f'populate network address: {args} / {kwargs}')
        for k, v in kwargs.items():
            if not callable(getattr(self, k)):
                setattr(self, k, v)
                continue
            continue
        return
