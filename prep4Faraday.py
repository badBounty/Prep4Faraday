import pandas as pd
import json
import sys

from Helper.parser import FaradayHelper

if len(sys.argv) < 2:
	print('Please provide an output name!')
	print('Example usage: py prep4Faraday.py output.xml')
	sys.exit(0)


faradayHelper = FaradayHelper()

with open('Config/SeverityConfig.json') as json_file:
    severity_data = json.load(json_file)
    
with open('Config/InputConfig.json') as json_file:
    input_data = json.load(json_file)

final_df_list = list()
for data in input_data:
	try:
		new_df = pd.read_csv('Input/' + data['Filename'])
	except FileNotFoundError:
		print('File ' + data['Filename'] + ' was not found, continuing with the rest')
		continue

	if data['Service'] == 'Acunetix':
		print('Parsing ' + data['Filename'] + ' from ' + data['Service'])
		new_df = faradayHelper.processAcu(new_df)
		final_df_list.append(new_df)

	elif data['Service'] == 'Nessus':
		print('Parsing ' + data['Filename'] + ' from ' + data['Service'])
		new_df = faradayHelper.processNessus(new_df)
		final_df_list.append(new_df)

	elif data['Service'] == 'Nmap':
		print('Parsing ' + data['Filename'] + ' from ' + data['Service'])
		new_df = faradayHelper.processNmap(new_df)
		final_df_list.append(new_df)

	else:
		print('File ' + data['Filename'] + ' service is not supported')

#Here we get the final dataframe
final_df = pd.concat(final_df_list, ignore_index=True)

final_df.loc[final_df.Severity == 'low', 'Severity'] = 'Low'
final_df.loc[final_df.Severity == 'medium', 'Severity'] = 'Medium'
final_df.loc[final_df.Severity == 'high', 'Severity'] = 'High'
final_df.loc[final_df.Severity == 'informational', 'Severity'] = 'Informational'

#Modify Severity from SeverityConfig.json

for data in severity_data:
    final_df = faradayHelper.modifySeverity(final_df, data['Name'], data['Severity'])

outputName = sys.argv[1]

final_df = final_df[final_df.Severity != 'Informational']

if '.xml' in outputName:
	faradayHelper.generateOutput(final_df, outputName)
else:
	outputName = outputName+'.xml'
	faradayHelper.generateOutput(final_df, outputName)
