import yaml
import streamlit as st
from yaml.loader import SafeLoader
import streamlit_authenticator as stauth
from streamlit_authenticator.utilities.exceptions import (CredentialsError,
                                                          ForgotError,
                                                          LoginError,
                                                          RegisterError,
                                                          ResetError,
                                                          UpdateError) 
import Authentication
import pandas as pd


# Loading config file
with open('config.yaml', 'r', encoding='utf-8') as file:
    config = yaml.load(file, Loader=SafeLoader)

# Creating the authenticator object
authenticator = Authentication.Authenticate(
    config['credentials'],
    config['cookie']['name'],
    config['cookie']['key'],
    config['cookie']['expiry_days'],
)

if not (config['credentials']['admins'] or st.session_state["authentication_status"]):
    st.title("No Admin avalaiable crerate one.")
    try:
        account = authenticator.register_user(isAdmin = True)
        if account:
            config['credentials']['admins'].append(account)
            st.success(f'User registered successfully {account}. Refresh the Page')

    except RegisterError as e:
        st.error(e)


else:
    try:
        authenticator.login()
    except LoginError as e:
        st.error(e)
    
    if st.session_state["authentication_status"]:
        authenticator.logout()
        st.write(f'Welcome *{st.session_state["name"]}*')
    elif st.session_state["authentication_status"] is False:
        st.error('Username/password is incorrect')


if st.session_state["authentication_status"]:
    
    if st.session_state['username'] in set(config['credentials']['admins']):

        try:
            st.title("Users Details")
            st.table(pd.DataFrame(config['credentials']['user_details']).transpose()[[
                'name',
                'mobile',
                'email',
                'account_type',
                'date_of_birth',
            ]])

            account = authenticator.register_user()
            if account:
                st.success(f'User registered successfully {account}.')

        except RegisterError as e:
            st.error(e)

    else:

        authenticator.transaction(st.session_state['username'])

        st.title("Past Transactions")
        st.table(pd.DataFrame(config['credentials']['user_details'][st.session_state['username']]['transactions']).transpose().tail(10))        
        

    try:
        if authenticator.reset_password(st.session_state["username"]):
            st.success('Password modified successfully')
    except ResetError as e:
        st.error(e)
    except CredentialsError as e:
        st.error(e)


with open('config.yaml', 'w', encoding='utf-8') as file:
    yaml.dump(config, file, default_flow_style=False)