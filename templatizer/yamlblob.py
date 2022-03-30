
import yaml


def string_as_block(dumper, data):
    if '\n' in data:
        return dumper.represent_scalar('tag:yaml.org,2002:str', data, style='|')
    return dumper.represent_scalar('tag:yaml.org,2002:str', data)


yaml.add_representer(str, string_as_block)


class YamlBlob(Templatable):

    def data(self):
        raise NotImplementedError('data() must be implemented on ConfigurationData')

    def generate(self):
        return yaml.dump(self.data())
