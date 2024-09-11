from flask import Flask, request, render_template, json, jsonify

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/transform', methods=['POST'])
def get_terraform_resource():
    data = request.get_json()

    spec = data.get('spec', {})
    gc_spec = spec.get('gc_spec', {})
    waf_exclusion_rules = gc_spec.get('waf_exclusion_rules', [])


    rules = ""
    for rule in waf_exclusion_rules:
        exact_value = rule.get('exact_value')
        path_regex = rule.get('path_regex')
        methods = rule.get('methods', [])
        metadata_items = rule.get('metadata', {})
        metadata = "\n".join([f" {key} = \"{value}\"" for key, value in metadata_items.items()])
        detection_control = rule.get('app_firewall_detection_control', {})
        exclude_signatures = detection_control.get('exclude_signature_contexts', [])
        ctx = ""

        for contxt in exclude_signatures:
            signature_id = contxt.get('signature_id')
            context = contxt.get('context')
            context_name = contxt.get('context_name')
            context_string = "\n".join(["exclude_signature_contexts {", "signature_id = {sig}".format(sig=signature_id), 'context = "{ctx}"'.format(ctx=context), 'context_name = "{ctn}"'.format(ctn=context_name),"}"])
            ctx += context_string
            ctx += "\n"

        terraform_content = [
                'waf_exclusion_rules {',
                    "metadata {",
                        "{}".format(metadata),
                    "}",
                    'methods = {}'.format(methods).replace("'", '"'),
                    '\nexact_value = "{}"'.format(exact_value),
                    'path_regex = "{}"'.format(path_regex).replace("\\", "\\\\"),
                    "app_firewall_detection_control {",
                    '    {}'.format(ctx),
                    "}",
            "}\n"]
        #return jsonify({"terraform_resource": "\n".join(terraform_content)})
        rules += "".join(terraform_content)

    return jsonify({"terraform_resource": rules})


if __name__ == '__main__':
    app.run(host='0.0.0.0',debug=True)
