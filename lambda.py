import urllib
import uuid
import os
import json
import boto3
import pandas as pd
import time
import requests
import gzip
import numpy as np
import base64

# import classification
# import correlation
# import ui

s3_client = boto3.client("s3")
sagemaker_client = boto3.client(service_name='sagemaker-runtime')

# technique_endpoint_name = 'seshat-technique-endpoint'
technique_endpoint_name = os.environ["technique_endpoint_name"]

# correlation_endpoint_name = 'seshat-correlation-endpoint'
correlation_endpoint_name = os.environ["correlation_endpoint_name"]

content_type = "application/json"

def create_campaigns(bucket, correlation_output_prefix):

	func = "create_campaign"

	s3_client = boto3.client("s3")

	# insert lb url in host
	# host = "http://bastet-1365449408.ca-central-1.elb.amazonaws.com:8000/"
	lb_url = os.environ["ui_lb_url"]
	host = f"http://{lb_url}:8000/"

	print(f"{func}: Get cookies for UI")
	s = requests.Session()
	s.get(host+"login")

	cookies = s.cookies.get_dict()

	csrf = cookies["csrftoken"]

	headers = {"X-CSRFToken": csrf, "Accept": "application/json"}

	username = "maestro"
	password = "Y2hhbmdlbWU="

	password = base64.b64decode(password)

	response = s.post(f"{host}login/?next", 
							data={"username": username, "password": password, "csrfmiddlewaretoken": csrf})
	
	
	print(f"login successful: {response.status_code == 404}")

	# -------------------------------------------------------------------------------

	input_object_key = f"{correlation_output_prefix}aggregates.json"
	input_local_filename = "/tmp/aggregates.json"

	print(f"{func}: Download the aggregates json with mapped flow ids")
	s3_client.download_file(bucket, input_object_key, input_local_filename)

	df = pd.read_json(input_local_filename)
	df['start_time'] = df['start_time'].dt.strftime('%Y-%m-%d %H:%M:%S')
	df['finish_time'] = df['finish_time'].dt.strftime('%Y-%m-%d %H:%M:%S')
	df['avg_time'] = df['avg_time'].dt.strftime('%Y-%m-%d %H:%M:%S')

	flows = np.sort(df["flow-id"].unique())

	flow_campaign_map = {}

	# event_threshold = 3
	# tac_threshold = 1

	event_threshold = int(os.environ["event_threshold"])
	tac_threshold = int(os.environ["tac_threshold"])

	for flow in flows:
		print(f"{func}: Evaluating for flow: {flow}")
		df_cluster = df.loc[df["flow-id"] == flow]
		# print(min_time, max_time)

		# "mapped_data": {
		#     "TTP": {
		#         "TACTICS": [],
		#         "TECHNIQUES": [
		#             1570
		#         ]
		#     },
		#     "UID": "621",
		#     "MESSAGE": "sentinelone Remote FileCopy",
		#     "HOSTNAME": "host5",
		#     "SOURCE_IP": "192.168,10.5",
		#     "TIMESTAMP": "2023-04-13 20:56:42+00:00",
		#     "DESTINATION_IP": "192.168,10.5"
		# }

		events = []

		for i in range(len(df_cluster)):
			row = df_cluster.iloc[i].to_dict()
			raw_data=row
			tac = row["tac"]
			if(len(tac) < tac_threshold):
				continue
			tech = row["tech"]
			tech = [int(t[1:]) for t in tech]
			mapped_data = {"TTP": {"TACTICS": tac, "TECHNIQUES": tech}}
			mapped_data["suggested_ttp"] = tac
			mapped_data["UID"] = row["alert_id"]
			mapped_data["SOURCE_IP"] = row["src"]
			mapped_data["DESTINATION_IP"] = row["dst"]
			mapped_data["HOSTNAME"] = row["name"]
			mapped_data["MESSAGE"] = row["name"]
			mapped_data["TIMESTAMP"] = row["finish_time"]
			for key, value in raw_data.items():
				raw_data[key] = str(value)
			events.append({"raw_data" : raw_data, "mapped_data" : mapped_data})

		if(len(events) < event_threshold):
			print(f"{func}: Length of list of events is less than threshold set. Skip creation of campaign. length: {len(events)}")
			continue
		
		print(f"{func}: Create request file and convert to gzip")
		req = json.dumps(events)
		req = gzip.compress(bytes(req, "utf-8"))
		open("/tmp/req.gzip", "wb").write(req)

		print(f"{func}: Create payload")
		payload = {"name" : flow, "description": "autmoatically created alerts", "auto_extract_iocs": "true"}

		files=[('details',('req.gzip',open('/tmp/req.gzip','rb'),'application/octet-stream'))]

		print(f"{func}: Sending campaign create request")

		response = s.post(f"{host}api/v2/campaign/", data=payload, files=files, cookies=cookies, headers=headers)
		print(f"{func}: Got response", response)

		if(int(response.status_code / 100) != 2):
			print(f"{func}: Campaign creation failed")
			print(response.content)

		response = json.loads(response.content)
		campaign_id = response["id"]

		flow_campaign_map[flow] = campaign_id

	print(f"{func}: Final flow id maps to campaign ids")

	print(flow_campaign_map)

def split_s3_path(s3_path):
    path_parts=s3_path.replace("s3://","").split("/")
    bucket=path_parts.pop(0)
    key="/".join(path_parts)
    return bucket, key

def create_correlation(bucket, input_object_key, correlation_output_prefix, unique_id):

	func = "create_correlation"

	output_object_key = f"{correlation_output_prefix}aggregates.json"
	output_local_filename = "/tmp/aggregates.json"

	# request_object_key = "request/req.json"
	request_object_key = os.environ["correlation_request_object_key"]

	try:
		print(f"{func}: Create request body for correlation model")
		request_body = {"object_key": input_object_key, "bucket": bucket, "correlation_output_prefix": correlation_output_prefix}
		# request_body = {"bucket": "input-alerts", "object_key": "temp/cic17.json", "uuid": ""}

		print(f"{func}: Request body created {request_body}")

		#Serialize data for endpoint
		data = json.loads(json.dumps(request_body))
		with open('/tmp/req.json', 'w') as f:
			json.dump(data, f)

		s3_req_location = f"s3://{bucket}/{request_object_key}"
		print(f"{func}: Upload request to s3. object key : {request_object_key}")
		s3_client.upload_file("/tmp/req.json", bucket, request_object_key)
		print(f"{func}: Uploaded request")

		print(f"{func}: Invoking correlation endpoint")

		result = sagemaker_client.invoke_endpoint_async(
			EndpointName = correlation_endpoint_name,
			ContentType=content_type,
			InputLocation=s3_req_location
		)

		#Parse results
		print(f"{func}: Got async response: {result}")

		if(not str(result["ResponseMetadata"]["HTTPStatusCode"]).startswith("2")):
			raise("Got non 200 response")

		# Load data from s3, the path is configured from the async config
		print(f"{func}: Response will be saved to : ")
		s3_output_bucket, s3_output_object = split_s3_path(result["OutputLocation"])
		print(f"s3 output bucket : {s3_output_bucket}")
		print(f"s3 output object : {s3_output_object}")

		print(f"{func}: Waiting for correlation process to complete")

		while True:
			try:
				s3_client.head_object(Bucket = s3_output_bucket, Key = s3_output_object)
				print(f"{func}: Output object created.")
				break
			except Exception as e:
				# wait = 60
				wait = int(os.environ["correlation_wait_time"])
				print(f"{func}: Output object not created yet. Will check back in {wait} seconds.")
				time.sleep(wait)

		print(f"{func}: Download output objects")
		s3_client.download_file(s3_output_bucket, f"{correlation_output_prefix}cluster_output.json", "/tmp/cluster_output.json")
		s3_client.download_file(s3_output_bucket, f"{correlation_output_prefix}alert_output.json", "/tmp/alert_output.json")
		s3_client.download_file(s3_output_bucket, f"{correlation_output_prefix}flow_output.json", "/tmp/flow_output.json")
		print(f"{func}: Output objects downloaded")

		clusters = json.load(open("/tmp/cluster_output.json"))
		agg_alerts = json.load(open("/tmp/alert_output.json"))
		flows = json.load(open("/tmp/flow_output.json"))

		# old: The cluster id is the campaign id. The alert id is already present for each agg_alert, which is the event
		# new: The flow id is the campaign id. The alert id is already present for each agg_alert, which is the event. cluster id is of no use.

		# print(clusters)

		# for each alerts we need to add flow id.

		print(f"{func}: Add flow id to aggreagated alerts")

		for k in flows:
			flow_clusters = k["cluster_ids"]
			for i in flow_clusters:
				for j in clusters[i]["cluster_aggalertids"]:
					agg_alerts[j]["flow-id"] = k["Flow_id"]

		print(f"{func}: Flow Id updated")
		
		json.dump(agg_alerts, open(output_local_filename, "w"))

		print(f"{func}: Upload the updated response json file")
		s3_client.upload_file(output_local_filename, bucket, output_object_key)
		print(f"{func}: Upload complete")
	
	except Exception as e:
		print(e)
		raise(e)

def label_techniques(bucket, input_object_key, output_object_key):

	func = "label_techniques"

	# technique_lookup_object = f"lambda/data.csv"
	technique_lookup_object = os.environ["technique_lookup_object"]
	technique_lookup_local = f"/tmp/data.csv"

	try:
		print(f"{func}: Checking for Lookup table for alerts")
		s3_client.head_object(Bucket = bucket, Key = technique_lookup_object)
		print(f"{func}: Lookup object present. Downloading...")
		s3_client.download_file(bucket, technique_lookup_object, technique_lookup_local)
		print(f"{func}: Compelted lookup object download")
	except Exception as e:
		print(f"{func}: Lookup table not present. Create empty table")
		df = pd.DataFrame(columns=["alerts", "techniques"])
		df.to_csv(technique_lookup_local)
		print(f"{func}: Empty lookup table created")
	df = pd.read_csv(technique_lookup_local)

	input_local_filename = "/tmp/input.json"
	output_local_filename = "/tmp/output.json"

	print(f"{func}: Download object created for label classification")

	# got log file put each line in the csv file row
	s3_client.download_file(bucket, input_object_key, input_local_filename)

	print(f"{func}: Downloaded object")

	# input_df = pd.read_json(input_local_filename)
	input_df = json.load(open(input_local_filename, "r"))

	try:
		progress = 0
		print(f"{func}: Start technique labelling")
		for i in range(len(input_df)):
			line = input_df[i]["name"]

			is_cached = df["alerts"].eq(line).any()
			if(is_cached):
				# print("Use Cached")
				# print(df[df["alerts"]==line].iloc[0]["techniques"])
				# print(type(df[df["alerts"]==line].iloc[0]["techniques"]))
				input_df[i]["tech"] = df[df["alerts"]==line].iloc[0]["techniques"]
			else:
				# print("Not cached")

				request_body = {"input": line}

				#Serialize data for endpoint
				data = json.loads(json.dumps(request_body))
				payload = json.dumps(data)

				#Endpoint invocation
				technique_endpoint_response = sagemaker_client.invoke_endpoint(
					EndpointName=technique_endpoint_name,
					ContentType=content_type,
					Body=payload)

				#Parse results
				result = json.loads(technique_endpoint_response['Body'].read().decode())

				input_df[i]["tech"] = result["labels"]["techniques"]
				temp_df = pd.Series({"alerts": line, "techniques": input_df[i]["tech"]})
				temp_df = pd.DataFrame(temp_df).T
				df = pd.concat([df,temp_df], ignore_index=True)
			
			if(progress < int((i / len(input_df)) * 100)):
				progress = int((i / len(input_df)) * 100)
				print("Progress percentage: ", progress)
		print("Progress percentage: ", 100)

		json.dump(input_df, open(output_local_filename, "w+"))

		print(f"{func}: Save lookup table")
		df.to_csv(technique_lookup_local, index=False)

		print(f"{func}: Upload updated input object to {output_object_key}")
		s3_client.upload_file(output_local_filename, bucket, output_object_key)
		print(f"{func}: Upload complete")

		print(f"{func}: Upload lookup table to {technique_lookup_object}")
		s3_client.upload_file(technique_lookup_local, bucket, technique_lookup_object)
		print(f"{func}: Upload complete")

	
	except Exception as e:
		print(e)
		raise(e)

def lambda_handler(event, context):
	func = "lambda_handler"

	bucket = event["Records"][0]["s3"]["bucket"]["name"]
	input_object_key = urllib.parse.unquote_plus(event["Records"][0]["s3"]["object"]["key"], encoding = "utf-8")

	unique_id = str(uuid.uuid4())
	# output_prefix = "output/"
	output_prefix = os.environ["output_prefix"]
	correlation_input = f"{output_prefix}{unique_id}/classification_out/input.json"
	correlation_output_prefix = f"{output_prefix}{unique_id}/aggregates/"
	
	print(f"{func}: Created object:")
	print(f"{func}: bucket: {bucket}")
	print(f"{func}: key: {input_object_key}")

	try:

		print(f"{func}: Starting labelling techniques")
		# classification.label_techniques(bucket, input_object_key, correlation_input)
		label_techniques(bucket, input_object_key, correlation_input)
		print(f"{func}: Completed labelling techniques")
		
		print(f"{func}: Starting correlation")
		# correlation.create_correlation(bucket, correlation_input, correlation_output_prefix, unique_id)
		create_correlation(bucket, correlation_input, correlation_output_prefix, unique_id)
		print(f"{func}: Completed correlation")

		print(f"Starting campaign creation")
		# ui.create_campaigns(bucket, correlation_output_prefix)
		create_campaigns(bucket, correlation_output_prefix)
		print(f"{func}: Complete campaign creation")

	except Exception as e:
		print(e)
		raise(e)
