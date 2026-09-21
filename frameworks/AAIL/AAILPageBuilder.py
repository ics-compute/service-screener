from frameworks.FrameworkPageBuilder import FrameworkPageBuilder


class AAILPageBuilder(FrameworkPageBuilder):
    def init(self):
        super().init()
        self.template = 'default'
