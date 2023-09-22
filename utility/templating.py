import yaml
from framework import config
from jinja2 import Environment, FileSystemLoader


def to_nice_yaml(a, indent=2, **kw):
    """
    This is a j2 filter which allows you from dictionary to print nice
    human-readable yaml.

    Args:
        a (dict): dictionary with data to print as yaml
        indent (int): number of spaces for indent to be applied for whole
            dumped yaml. First line is not indented! (default: 2)
        *kw: Other keywords arguments which will be passed to yaml.dump

    Returns:
        str: transformed yaml data in string format

    """
    transformed = yaml.dump(
        a,
        Dumper=yaml.Dumper,
        indent=indent,
        allow_unicode=True,
        default_flow_style=False,
        **kw,
    )
    return transformed


class Templating:
    """
    Class which provides all functionality for templating
    """

    def __init__(self, base_path=config.ENV_DATA["template_dir"]):
        """
        Constructor for Templating class

        Args:
            base_path (str): path from which should read the jinja2 templates
                default(NOOBAA_SA_CI_ROOT_DIR/templates)

        """
        self._base_path = base_path

    def render_template(self, template_path, data):
        """
        Render a template with the given data.

        Args:
            template_path (str): location of the j2 template from the
                self._base_path
            data (dict): the data to be formatted into the template

        Returns:
             rendered template

        """
        j2_env = Environment(loader=FileSystemLoader(self._base_path), trim_blocks=True)
        j2_env.filters["to_nice_yaml"] = to_nice_yaml
        j2_template = j2_env.get_template(template_path)
        return j2_template.render(**data)
