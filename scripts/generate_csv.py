import csv
import glob
import yaml

for folder in ("leaked", "malicious"):
    yml_files = glob.glob(f"../{folder}/*.yml", recursive=True)
    csv_file = open(f"../csv/{folder}.csv", "w")
    csv_writer = csv.writer(csv_file)
    csv_writer.writerow(["name","status","source","description","references","date","author","issuer","timestamp","serial"])

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
            csv_writer.writerow([
                yml["name"],
                yml["meta"]["status"],
                yml["meta"]["source"],
                yml["meta"]["description"].strip().replace("\n", " "),
                yml["meta"]["references"],
                yml["meta"]["date"],
                yml["meta"]["author"],
                yml["issuer"],
                str(yml["timestamp"]) if "timestamp" in yml else "",
                serial
            ])
    csv_file.close()
