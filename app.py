import streamlit as st
import pandas as pd
from PIL import Image
import hashlib
import pickle

df = pd.read_csv("kdd.csv")
pipe = pickle.load(open("pipe.pkl", "rb"))

def make_hashes(password):
   return hashlib.sha256(str.encode(password)).hexdigest()

def check_hashes(password,hashed_text):
   if make_hashes(password) == hashed_text:
      return hashed_text
   return False
import sqlite3
conn = sqlite3.connect('data.db')
c = conn.cursor()
def create_usertable():
   c.execute('CREATE TABLE IF NOT EXISTS userstable(username TEXT,password TEXT)')
def add_userdata(username,password):
   c.execute('INSERT INTO userstable(username,password) VALUES (?,?)',(username,password))
   conn.commit()
def login_user(username,password):
   c.execute('SELECT * FROM userstable WHERE username =? AND password = ?',(username,password))
   data = c.fetchall()
   return data
def view_all_users():
   c.execute('SELECT * FROM userstable')
   data = c.fetchall()
   return data



def main():
   st.title("CYBER ATTACK DETECTION MODEL ")
   menu = ["Home","Login","SignUp"]
   choice = st.sidebar.selectbox("Menu",menu)



   if choice == "Home":
      st.subheader("Home")

      st.write("Welcome to the CYBER ATTACK app! This app detects the type of cyber attack based on various network features.")
      st.write("To get started, log in or create a new account from the sidebar menu.")

   elif choice == "Login":
      st.subheader("Login Section")
      username = st.sidebar.text_input("User Name")
      password = st.sidebar.text_input("Password",type='password')
      if st.sidebar.checkbox("Login"):
         create_usertable()
         hashed_pswd = make_hashes(password)
         result = login_user(username,check_hashes(password,hashed_pswd))
         if result:
            st.success("Logged In as {}".format(username))
            st.info("Duration: Length of time duration of the connection")
            duration = st.number_input('Duration')
            st.info("Protocol_type: Protocol used in the connection,0 for icmp, 1 for tcp, 2 for udp")
            p_type= st.selectbox ('Protocol type', df['protocol_type'].unique())
            st.text("Flag: Status of the connection – Normal or Error")
            st.info("'SF':0, 'S0':1, 'REJ':2, 'RSTR':3, 'RSTO':4, 'SH':5, 'S1':6, 'S2':7, 'RSTOS0':8, 'S3':9, 'OTH':10")
            flag = st.selectbox('flag', df['flag'].unique())
            st.info("Src_bytes: Number of data bytes transferred from source to destination in single connection")
            src_bytes = st.number_input('src_bytes')
            st.info("Dst_bytes: Number of data bytes transferred from destination to source in single connection")
            dst_bytes = st.number_input('dst_bytes')
            st.info("Logged_in Login Status: 1 if successfully logged in; 0 otherwise")
            logged_in = st.number_input('Logged_in')
            st.info("Count: Number of connections to the same destination host as the current connection in the past two seconds")
            count = st.number_input('Count')
            st.info(" Srv_count: Number of connections to the same service (port number) as the current connection"
                    " in the past two seconds")
            srv_count = st.number_input('srv_count')
            st.info("Serror_rate: The percentage of connections that have activated the "
                    "flag (4) s0, s1, s2 or s3, among the connections aggregated in count ")
            s_error_rate = st.number_input('serror_rate')
            st.info("Rerror_rate: The percentage of connections that have activated the flag (4) REJ,"
                    " among the connections aggregated in count")
            r_error_rate = st.number_input('rerror_rate')
            st.info("Same_srv_rate: The percentage of connections that were to the same service, "
                    "among the connections aggregated in count ")
            same_srv_rate = st.number_input('same_srv_rate')
            st.info("Diff_srv_rate: The percentage of connections that were to different services, "
                    "among the connections aggregated in count")
            diff_srv_rate = st.number_input('diff_srv_rate')
            st.info("Srv_diff_host_ rate: The percentage of connections that were to different destination "
                    "machines among the connections aggregated in srv_count")
            srv_diff_host_rate = st.number_input('srv_diff_host_rate')
            st.info("Dst_host_count: Number of connections having the same destination host IP address")
            dst_host_count = st.number_input('dst_host_count')
            st.info("Dst_host_count: Number of connections having the same destination host IP address")
            st_host_srv_count = st.number_input('st_host_srv_count')
            st.info("Dst_host_diff srv_rate: The percentage of connections that were to different services,"
                    " among the connections aggregated in dst_host_count")
            dst_host_diff_srv_rate = st.number_input('dst_host_diff_srv_rate')
            st.info("Dst_host_same src_port_rate: The percentage of connections that were to the same source port, "
                    "among the connections aggregated in dst_host_srv_count")
            dst_host_same_src_port_rate = st.number_input('dst_host_same_src_port_rate')
            st.info("Dst_host_srv diff_host_rate: The percentage of connections that were to different destination machines,"
                    "among the connections aggregated in dst_host_srv_count")
            dst_host_srv_diff_host_rate = st.number_input('dst_host_srv_diff_host_rate')
            st.text("")
            label = st.number_input('label')

            if st.button("Predict Attack"):

               y_test = pipe.predict([[duration,p_type,flag,src_bytes,dst_bytes,logged_in,count,srv_count,
                                      s_error_rate,r_error_rate,same_srv_rate,diff_srv_rate,srv_diff_host_rate,dst_host_count,
                                       st_host_srv_count,dst_host_diff_srv_rate,dst_host_same_src_port_rate,dst_host_srv_diff_host_rate,
                                       label]])[0]
               st.success(y_test)

               if y_test =='normal':
                  st.info("This refers to legitimate or authorized activities on a computer system that do not pose a security threat or violate any security policies. These activities are considered normal and expected behavior.")
               elif y_test == 'probe':
                  st.info("This is an attack in which an attacker scans a network or system to gather information about its vulnerabilities, configuration, and topology.The purpose of this type of attack is to identify potential targets for further attacks.")
               elif y_test == 'dos':
                  st.info("This is an attack in which an attacker floods a network or server with traffic or requests, making it unavailable to legitimate users. This type of attack can cause system crashes, slow performance, and loss of data.")
               elif y_test == 'u2r':
                  st.info("This type of attack involves an unauthorized user attempting to gain root or administrative privileges on a system. This is typically done by exploiting vulnerabilities in the software or operating system running on the system. Once the attacker gains root access, they have complete control over the system and can carry out further attacks or steal sensitive data.")
               else:
                  st.info("This type of attack involves an unauthorized user attempting to gain access to a system by exploiting vulnerabilities in the system's remote access protocols, such as SSH or Telnet. Once the attacker gains access to the system, they attempt to escalate their privileges to gain more control.")


         else:
            st.warning("Incorrect Username/Password")
   elif choice == "SignUp":
      st.subheader("Create New Account")
      new_user = st.text_input("Username")
      new_password = st.text_input("Password",type='password')
      if st.button("Signup"):
         create_usertable()
         add_userdata(new_user,make_hashes(new_password))
         st.success("You have successfully created a valid Account")
         st.info("Go to Login Menu to login")
if __name__ == '__main__':
   main()