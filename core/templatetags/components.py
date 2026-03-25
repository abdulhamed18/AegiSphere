"""Template tags for UI components. Provides block-based card usage."""
from django import template

register = template.Library()


@register.tag(name="card")
def do_card(parser, token):
    """
    Usage: {% card "Optional Title" %}...content...{% endcard %}
    Renders a card wrapper with optional title.
    """
    bits = token.split_contents()
    if len(bits) > 2:
        raise template.TemplateSyntaxError("'card' tag takes at most one argument (title)")
    title_expr = parser.compile_filter(bits[1]) if len(bits) == 2 else None
    nodelist = parser.parse(("endcard",))
    parser.delete_first_token()
    return CardNode(nodelist, title_expr)


class CardNode(template.Node):
    def __init__(self, nodelist, title_expr):
        self.nodelist = nodelist
        self.title_expr = title_expr

    def render(self, context):
        title = self.title_expr.resolve(context) if self.title_expr else None
        from django.utils.html import escape
        out = '<div class="bg-card border border-subtle rounded-xl p-5 smooth-transition hover:border-blue-500/30">'
        if title:
            out += f'<div class="flex justify-between items-center mb-4"><h2 class="text-lg font-medium text-text-primary">{escape(str(title))}</h2></div>'
        out += self.nodelist.render(context)
        out += "</div>"
        return out
