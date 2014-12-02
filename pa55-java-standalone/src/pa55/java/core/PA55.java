/*
   Copyright 2014 Anirban Basu

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
 */

package pa55.java.core;

import java.io.Console;
import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Scanner;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 * A class to generate strong passwords using PBKDF2 given a 
 * master secret and a password hint.
 * 
 * @author Anirban Basu
 *
 */
public class PA55 {
	private final static String CHAR_ENCODING = "UTF-8";
	private final static String APP_VERSION = "1.0";
	
	/**
	 * A list of acceptable HMAC hash functions.
	 * 
	 * @author Anirban Basu
	 *
	 */
	public enum HMACHashFunction {
		SHA1,
		SHA256,
		SHA512
	}
	
	private String masterSecret;
	private String passwordHint;
	private Integer pbkdfRounds;
	private Integer pbkdfLength;
	private HMACHashFunction pbkdfAlgorithm;
	private String pbkdfGeneratedPassword;
	
	public String getMasterSecret() {
		return masterSecret;
	}
	public void setMasterSecret(String masterSecret) {
		this.masterSecret = masterSecret;
	}
	public String getPasswordHint() {
		return passwordHint;
	}
	public void setPasswordHint(String passwordHint) {
		this.passwordHint = passwordHint;
	}
	public Integer getPbkdfRounds() {
		return pbkdfRounds;
	}
	public void setPbkdfRounds(Integer pbkdfRounds) {
		this.pbkdfRounds = pbkdfRounds;
	}
	public Integer getPbkdfLength() {
		return pbkdfLength;
	}
	public void setPbkdfLength(Integer pbkdfLength) {
		this.pbkdfLength = pbkdfLength;
	}
	public String getPbkdfGeneratedPassword() {
		return pbkdfGeneratedPassword;
	}
	public HMACHashFunction getPbkdfAlgorithm() {
		return pbkdfAlgorithm;
	}
	public void setPbkdfAlgorithm(HMACHashFunction pbkdfAlgorithm) {
		this.pbkdfAlgorithm = pbkdfAlgorithm;
	}
	
	/**
	 * Method to generate a strong password from the input parameters using PBKDF2.
	 * 
	 * @throws UnsupportedEncodingException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 */
	public void generatePBKDF2Password() throws UnsupportedEncodingException, NoSuchAlgorithmException, InvalidKeySpecException {
		Digest digest = null;
		switch(pbkdfAlgorithm) {
			case SHA1:
				digest = new SHA1Digest();
				break;
			case SHA256:
				digest = new SHA256Digest();
				break;
			case SHA512:
				digest = new SHA512Digest();
				break;
		}
		PKCS5S2ParametersGenerator generator = new PKCS5S2ParametersGenerator(digest);
		generator.init(masterSecret.getBytes(CHAR_ENCODING), passwordHint.getBytes(CHAR_ENCODING), pbkdfRounds.intValue());
		byte [] password = ((KeyParameter)generator.generateDerivedParameters(pbkdfLength.intValue()*8)).getKey();
		pbkdfGeneratedPassword = Base64.encodeBase64String(password);
	}
	
	/**
	 * Method to test the password generation mechanism.
	 * 
	 * @throws UnsupportedEncodingException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 */
	public static void testGeneration () throws UnsupportedEncodingException, NoSuchAlgorithmException, InvalidKeySpecException {
		PA55 core = new PA55();
		core.setMasterSecret("test1234");
		core.setPasswordHint("1234test");
		core.setPbkdfRounds(500000);
		core.setPbkdfLength(9); //byte length, not the length in characters of the Base64 encoded string.
		core.setPbkdfAlgorithm(HMACHashFunction.SHA512);
		core.generatePBKDF2Password();
		System.out.println(core.getPbkdfGeneratedPassword());
	}
	
	public static void main (String[] args) throws UnsupportedEncodingException, NoSuchAlgorithmException, InvalidKeySpecException {
		System.out.println("**** This is a reference implementation version " + APP_VERSION + " of pa55. Please see the project page (http://anirbanbasu.github.io/pa55/) for details. ****\r\n");
		Console inputConsole = System.console(); //If it is available, we need Console for masking passwords.
		Scanner inputConsoleScanner;
		Scanner echoOptionScanner = new Scanner(System.in);
		boolean disableEcho = false;
		if(inputConsole!=null) {
			//We can hide the input, but should we? Ask the user.
			System.out.println("Do you want to hide the master secret and the password hint as you type them? Enter 1 to hide or 0 to not hide.");
			disableEcho = echoOptionScanner.nextInt() == 0? false : true;
		}
		String echoNotice;
		if(disableEcho) {
			inputConsoleScanner = new Scanner(inputConsole.reader());
			echoNotice = " (your input will NOT be visible as you type)";
		}
		else {
			inputConsoleScanner =  new Scanner(System.in);
			echoNotice =  " (your input will be visible as you type)";
		}
		PA55 core = new PA55();
		String lineInput = "";
		System.out.println("Enter master secret" + echoNotice);
		lineInput = (disableEcho? new String(inputConsole.readPassword()) : inputConsoleScanner.nextLine().trim());
		while(lineInput.length()==0) {
			System.out.println("Please enter a non-empty string" + echoNotice);
			lineInput = (inputConsole!=null? new String(inputConsole.readPassword()) : inputConsoleScanner.nextLine().trim());
		}
		core.setMasterSecret(lineInput);
		System.out.println("Enter password hint" + echoNotice);
		lineInput = (disableEcho? new String(inputConsole.readPassword()) : inputConsoleScanner.nextLine().trim());
		while(lineInput.length()==0) {
			System.out.println("Please enter a non-empty string" + echoNotice);
			lineInput = (inputConsole!=null? new String(inputConsole.readPassword()) : inputConsoleScanner.nextLine().trim());
		}
		core.setPasswordHint(lineInput);
		int choiceInput = 0;
		System.out.println("Choose desired length in characters:\r\n (0) default: 12 characters\r\n (1) 8 characters\r\n (2) 12 characters\r\n (3) 16 characters\r\n (4) 20 characters\r\n (5) 24 characters\r\n (6) 28 characters\r\n (7) 32 characters");
		choiceInput = inputConsoleScanner.nextInt();
		while(choiceInput < 0 || choiceInput > 7) {
			System.out.println("Please enter a choice between 0 and 7.");
			choiceInput = inputConsoleScanner.nextInt();
		}
		if(choiceInput == 0) {
			choiceInput = 2;
		}
		core.setPbkdfLength((choiceInput + 1) * 3);
		System.out.println("Choose the password iterations:\r\n (0) default: 500K\r\n (1) Low (10K)\r\n (2) 250K\r\n (3) 500K\r\n (4) 750K\r\n (5) 1M\r\n (6) 1.25M\r\n (7) 1.5M");
		choiceInput = inputConsoleScanner.nextInt();
		while(choiceInput < 0 || choiceInput > 7) {
			System.out.println("Please enter a choice between 0 and 7.");
			choiceInput = inputConsoleScanner.nextInt();
		}
		if(choiceInput == 0) {
			choiceInput = 3;
		}
		if(choiceInput != 1) {
			core.setPbkdfRounds(choiceInput * 250000);
		}
		else {
			core.setPbkdfRounds(10000);
		}
		System.out.println("Choose the HMAC algorithm:\r\n (0) default: SHA256\r\n (1) SHA1\r\n (2) SHA256\r\n (3) SHA512");
		choiceInput = inputConsoleScanner.nextInt();
		while(choiceInput < 0 || choiceInput > 3) {
			System.out.println("Please enter a choice between 0 and 3.");
			choiceInput = inputConsoleScanner.nextInt();
		}
		if(choiceInput == 0) {
			choiceInput = 2;
		}
		core.setPbkdfAlgorithm(HMACHashFunction.values()[choiceInput-1]);
		inputConsoleScanner.close();
		echoOptionScanner.close();
		System.out.print("Generating password...\r");
		core.generatePBKDF2Password();
		System.out.println("Your password is: " + core.getPbkdfGeneratedPassword());
	}
	
}
