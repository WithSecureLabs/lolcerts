import jinja2 

# Load the template file
templateLoader = jinja2.FileSystemLoader(searchpath="./")
templateEnv = jinja2.Environment(loader=templateLoader)
TEMPLATE_FILE = "yara_rule_template.j2"
template = templateEnv.get_template(TEMPLATE_FILE)

# from the upper directory, find all the yml files
import glob
yml_files = glob.glob("../**/*.yml", recursive=True)

# for each yml file, generate a yara file
for yml_file in yml_files:
    # Load the yml file
    import yaml
    with open(yml_file, 'r') as stream:
        try:
            yml = yaml.safe_load(stream)
        except yaml.YAMLError as exc:
            print(exc)
        
    # Generate the yara file
    yara_file = yml_file.replace(".yml", ".yar")

    # replace the yara file path to be in the yara/ directory
    yara_file = yara_file.replace("../", "../yara/")
    yara_file = yara_file.replace("/leaked", "")
    yara_file = yara_file.replace("/malicious", "")
    
    # serial is an array of strings, so we need to join them
    if len(yml['serial']) > 1:
        yml['serial'] = "\" or \"".join(yml['serial'])
    else:
        yml['serial'] = yml['serial'][0]
   
    yml['serial'] = "\"" + yml['serial'] + "\""

    # check if timestamp is in the yml file
    if 'timestamp' in yml:
        yml['timestamp'] = "pe.timestamp > " + str(yml['timestamp']) + " and"
    else:
        yml['timestamp'] = ""

    with open(yara_file, 'w') as f:
        f.write(template.render(yml=yml, 
        name=yml['name'],
        status=yml['meta']['source'],
        meta=yml['meta'],
        serial=yml['serial'],
        issuer=yml['issuer'],
        timestamp=yml['timestamp'],
        ))