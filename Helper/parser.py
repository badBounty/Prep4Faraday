import pandas
import json


class FaradayHelper():

	def modifySeverity(self, df, name, severity):
		df.loc[df.Name == name, 'Severity'] = severity
		return df

	def processAcu(self, df):

		filtered_df = df.loc[:,['Name','ModuleName','Details','Affects','Severity','Type','Impact','Description','Recommendation','CWEList/CWE/__cdata','CVSS/Score']]
		filtered_df = filtered_df[['Name','ModuleName','Details','Affects','Severity','Type','Impact','Description','Recommendation','CWEList/CWE/__cdata','CVSS/Score']]
		filtered_df.columns = ['Name','ModuleName','Details','Affects','Severity','Type','Impact','Description','Recommendation','CWEList/CWE/__cdata','CVSS/Score']
		return filtered_df

	def processNessus(self, df):

		filtered_df = df.loc[:,['Name','Plugin ID','Port','Host','Risk','Description','Solution','CVE','CVSS']]
		filtered_df['Type'] = 'Nessus'
		filtered_df['Impact'] = '-'
		filtered_df = filtered_df[['Name','Plugin ID','Port','Host','Risk','Type','Impact','Description','Solution','CVE','CVSS']]
		filtered_df.columns = ['Name','ModuleName','Details','Affects','Severity','Type','Impact','Description','Recommendation','CWEList/CWE/__cdata','CVSS/Score']

		return filtered_df

	def processNmap(self, df):

		filtered_df = df.loc[:,['Port','Hostname','State','Additional information']]
		filtered_df['Name'] = '-'
		filtered_df['ModuleName'] = '-'
		filtered_df['Type'] = 'Nmap'
		filtered_df['Impact'] = '-'
		filtered_df['Recommendation'] = '-'
		filtered_df['CWEList/CWE/__cdata'] = '-'
		filtered_df['CVSS/Score'] = '-'
		filtered_df = filtered_df[['Name','ModuleName','Port','Hostname','State','Type','Impact','Additional information','Recommendation','CWEList/CWE/__cdata','CVSS/Score']]
		filtered_df.columns = ['Name','ModuleName','Details','Affects','Severity','Type','Impact','Description','Recommendation','CWEList/CWE/__cdata','CVSS/Score']

		return filtered_df

	def generateOutput(self, df, outputName):

		with open("Output/"+outputName, "w+") as f:
			f.write("""<?xml version="1.0"?>
<ScanGroup ExportedOn="21/01/2020, 16:06:56">
<Scan>
		<Name><![CDATA[scan_name]]></Name>
		<ShortName><![CDATA[scan_short_name]]></ShortName>
		<StartURL><![CDATA[www.skyhdtvbrasil.com.br]]></StartURL>
		<StartTime><![CDATA[21/01/2020, 19:39:42]]></StartTime>
		<FinishTime><![CDATA[21/01/2020, 21:06:41]]></FinishTime>
		<ScanTime><![CDATA[86 minutes, 57 seconds]]></ScanTime>
		<Aborted><![CDATA[True]]></Aborted>
		<Responsive><![CDATA[True]]></Responsive>
		<Banner><![CDATA[]]></Banner>
		<Os><![CDATA[Unknown]]></Os>
		<WebServer><![CDATA[LiteSpeed]]></WebServer>
		<Technologies>
			<![CDATA[
					   
			]]>
		</Technologies>
		<Crawler StartUrl="https://www.skyhdtvbrasil.com.br">
		</Crawler>
		<ReportItems>""")
			i = 0
			for index, row in df.iterrows():
				i = i+1
				f.write("""
			<ReportItem id="1" color="red">
				<Name><![CDATA[%s]]></Name>
				<ModuleName><![CDATA[%s]]></ModuleName>
				<Details><![CDATA[%s]]></Details>
				<Affects><![CDATA[%s]]></Affects>
				<Parameter><![CDATA[]]></Parameter>
				<AOP_SourceFile><![CDATA[]]></AOP_SourceFile>
				<AOP_SourceLine></AOP_SourceLine>
				<AOP_Additional><![CDATA[]]></AOP_Additional>
				<IsFalsePositive><![CDATA[]]></IsFalsePositive>
				<Severity><![CDATA[%s]]></Severity>
				<Type><![CDATA[%s]]></Type>
				<Impact><![CDATA[%s]]></Impact>
				<Description><![CDATA[%s]]></Description>
				<DetailedInformation><![CDATA[Information]]></DetailedInformation>
				<Recommendation><![CDATA[%s]]></Recommendation>
				<TechnicalDetails>
				</TechnicalDetails>
				<CWEList>
				</CWEList>
				<CVEList>
				</CVEList>
				<CVSS>
				  <RC></RC>
				</CVSS>
				<CVSS3>
				</CVSS3>
				<References>
				</References>
			</ReportItem>""" % (row['Name'],row['ModuleName'],row['Details'],row['Affects'],row['Severity'],row['Type'],row['Impact'],row['Description'],row['Recommendation']))
		
		
			f.write("""
		</ReportItems>
	</Scan>
</ScanGroup>""")

		return