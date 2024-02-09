import glob
import yaml

for folder in ("leaked", "malicious"):
    yml_files = glob.glob(f"../{folder}/*.yml", recursive=True)
    csv_content = "name,status,source,description,references,date,author,issuer,timestamp,serial\n"

    # Generate the csv file for each folder
    for yml_file in yml_files:
        # Load the yml file
        with open(yml_file, 'r') as stream:
            try:
                yml = yaml.safe_load(stream)
            except yaml.YAMLError as exc:
                print(exc)
        for serial in yml["serial"]:
            # Generate the csv entry
            entry = ",".join([
                yml["name"],
                yml["meta"]["status"],
                yml["meta"]["source"],
                yml["meta"]["description"].strip().replace("\n", " ").replace(",", ""),
                yml["meta"]["references"].replace(",", ""),
                yml["meta"]["date"],
                yml["meta"]["author"].replace(",", ""),
                yml["issuer"],
                str(yml["timestamp"]) if "timestamp" in yml else "",
                serial
            ])
            csv_content += f"{entry}\n"
    with open(f"../csv/{folder}.csv", "w") as f:
        f.write(csv_content)
