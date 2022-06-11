{
   "targets":[
        {
           "target_name": "BUNDLE",

           "sources": ["bundle.cc","sha256.h","sha256.cc"],

            "conditions":[
                ["OS=='linux'", {

                    "libraries": [

                        "<!(pwd)/dilithium.so",
                        "<!(pwd)/kyber.so",
                        "<!(pwd)/sidh.so",
                        "<!(pwd)/sike.so",
                        "<!(pwd)/csidh.so",
                        "<!(pwd)/bliss.so",
                        "<!(pwd)/kyber_pke.so",

                    ]

                }],

                ["OS=='mac'", {

                    "libraries": [

                        "<!(pwd)/dilithium.so",
                        "<!(pwd)/kyber.so",
                        "<!(pwd)/sidh.so",
                        "<!(pwd)/sike.so",
                        "<!(pwd)/csidh.so",
                        "<!(pwd)/bliss.so",
                        "<!(pwd)/kyber_pke.so",

                    ]

                }],
                ["OS=='win'", {
                    "libraries": [
                        '<!(pwd)/dilithium.dll',
                        '<!(pwd)/kyber.dll',
                        '<!(pwd)/sidh.dll',
                        '<!(pwd)/sike.dll',
                        '<!(pwd)/csidh.dll',
                        '<!(pwd)/bliss.dll',
                        "<!(pwd)/kyber_pke.dll",
                    ]

                }]

            ],

        }

    ]

}