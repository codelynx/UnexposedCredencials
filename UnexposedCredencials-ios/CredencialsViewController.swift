//
//	ViewController.swift
//	UnexposedCredencials-ios
//
//	Created by Kaz Yoshikawa on 4/24/23.
//

import UIKit

class CredencialsViewController: UITableViewController {

	@IBOutlet weak var apiKeyLabel: UILabel!
	@IBOutlet weak var secretKeyLabel: UILabel!

	override func viewDidLoad() {
		super.viewDidLoad()
		// Do any additional setup after loading the view.
		self.apiKeyLabel.text = CREDENTIALS.shared["MY_API_KEY"] as? String
		self.secretKeyLabel.text = CREDENTIALS.shared["MY_SECERT_KEY"] as? String
	}


}

